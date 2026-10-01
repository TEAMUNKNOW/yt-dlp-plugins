"""yt-dlp plugin: OAuth 2.0 Device Authorization Grant (RFC 8628) engine.

This module implements a standards-compliant OAuth 2.0 Device Authorization
Grant client suitable for research and integration with yt-dlp.  It is
deliberately isolated from YouTube-specific authentication, PO Token
generation, BotGuard attestation, and any anti-bot claims.

IMPORTANT LIMITATIONS (as of 2024-11 / current yt-dlp):
- Official yt-dlp support for YouTube OAuth login was removed because
  YouTube-side restrictions made it non-functional.
- This plugin therefore does NOT override YoutubeIE and does NOT claim
  that obtained OAuth tokens will be accepted by YouTube Innertube,
  will generate PO Tokens, or will bypass any security controls.
- The OAuth engine is provided as a clean, testable, standards-compliant
  implementation that can be used for research or for future legitimate
  integration points should they appear.

Plugin discovery: yt-dlp loads public classes ending in ``IE`` from
``yt_dlp_plugins/extractor/``.  This module intentionally exposes no
public ``IE`` class that replaces YoutubeIE.  The OAuth machinery is
available for programmatic use and for any future supported hooks.

References:
- RFC 8628: OAuth 2.0 Device Authorization Grant
- Google OAuth 2.0 Device endpoints
- yt-dlp plugin architecture (namespace package ``yt_dlp_plugins``)
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
)

__all__ = [
    "OAuthConfig",
    "OAuthToken",
    "DeviceAuthorizationResponse",
    "OAuthClient",
    "OAuthPoller",
    "TokenStore",
    "FileTokenStore",
    "OAuthError",
    "AuthorizationDeniedError",
    "AuthorizationExpiredError",
    "ExpiredTokenError",
    "InvalidTokenError",
    "OAuthNetworkError",
    "InvalidClientError",
    "InvalidGrantError",
    "InvalidRequestError",
    "UnsupportedGrantTypeError",
    "CorruptedCacheError",
    "IncompatibleYtDlpError",
    "ConfigurationError",
    "redact_secrets",
    "get_oauth_client",
]

# ---------------------------------------------------------------------------
# Constants / endpoints (configurable, never scattered)
# ---------------------------------------------------------------------------

DEFAULT_DEVICE_ENDPOINT = "https://oauth2.googleapis.com/device/code"
DEFAULT_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
DEFAULT_SCOPE = "https://www.googleapis.com/auth/youtube"
DEFAULT_TIMEOUT = 30.0
DEFAULT_SAFETY_MARGIN = 60.0  # seconds before actual expiry to treat as expired
DEFAULT_POLL_INTERVAL = 5  # RFC 8628 default when server omits interval
SLOW_DOWN_INCREMENT = 5  # RFC 8628 §3.5
CACHE_FILENAME = "youtube_oauth2_token.json"
CACHE_DIR_NAME = "yt-dlp-oauth2"

logger = logging.getLogger("yt_dlp_plugins.extractor.youtube_oauth2")


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class OAuthError(Exception):
    """Base class for all OAuth-related errors raised by this module."""

    def __init__(self, message: str, *, error_code: str | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message

    def __str__(self) -> str:
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


class AuthorizationDeniedError(OAuthError):
    """User denied the authorization request (access_denied)."""


class AuthorizationExpiredError(OAuthError):
    """Device code expired before the user completed authorization."""


class ExpiredTokenError(OAuthError):
    """Access token (or refresh token) has expired."""


class InvalidTokenError(OAuthError):
    """Token data is malformed or fails validation."""


class OAuthNetworkError(OAuthError):
    """Network-level failure while talking to an OAuth endpoint."""


class InvalidClientError(OAuthError):
    """Client ID / secret rejected by the authorization server."""


class InvalidGrantError(OAuthError):
    """Refresh token or grant is invalid / revoked."""


class InvalidRequestError(OAuthError):
    """Malformed request sent to the authorization server."""


class UnsupportedGrantTypeError(OAuthError):
    """Server does not support the requested grant type."""


class CorruptedCacheError(OAuthError):
    """Persisted token cache is unreadable or structurally invalid."""


class IncompatibleYtDlpError(OAuthError):
    """Detected yt-dlp version / API is incompatible with this plugin."""


class ConfigurationError(OAuthError):
    """Missing or invalid configuration (e.g. no client_id)."""


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

_SECRET_KEYS = frozenset(
    {
        "access_token",
        "refresh_token",
        "device_code",
        "client_secret",
        "id_token",
    }
)


def redact_secrets(obj: Any) -> Any:
    """Recursively redact known secret fields from a structure for safe logging."""
    if isinstance(obj, Mapping):
        return {
            k: ("***REDACTED***" if k.lower() in _SECRET_KEYS else redact_secrets(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact_secrets(item) for item in obj)
    return obj


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OAuthConfig:
    """Immutable configuration for the OAuth client."""

    client_id: str
    client_secret: str | None = None
    scope: str = DEFAULT_SCOPE
    device_endpoint: str = DEFAULT_DEVICE_ENDPOINT
    token_endpoint: str = DEFAULT_TOKEN_ENDPOINT
    timeout: float = DEFAULT_TIMEOUT
    safety_margin: float = DEFAULT_SAFETY_MARGIN
    allow_insecure_endpoints: bool = False

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_id.strip():
            raise ConfigurationError("client_id is required and must be non-empty")
        if not self.allow_insecure_endpoints:
            for url in (self.device_endpoint, self.token_endpoint):
                if not url.lower().startswith("https://"):
                    raise ConfigurationError(
                        f"Insecure endpoint rejected (use allow_insecure_endpoints=True "
                        f"only for local tests): {url}"
                    )


@dataclass
class OAuthToken:
    """Strongly-typed OAuth token container."""

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    obtained_at: float = field(default_factory=time.time)
    expires_at: float | None = None

    def __post_init__(self) -> None:
        if self.expires_at is None and self.expires_in is not None:
            self.expires_at = self.obtained_at + float(self.expires_in)

    def is_expired(self, *, now: float | None = None, safety_margin: float = DEFAULT_SAFETY_MARGIN) -> bool:
        """Return True if the access token should be treated as expired."""
        if self.expires_at is None:
            return False
        if now is None:
            now = time.time()
        return now >= (self.expires_at - safety_margin)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OAuthToken:
        required = {"access_token"}
        missing = required - set(data.keys())
        if missing:
            raise InvalidTokenError(f"Token data missing required fields: {sorted(missing)}")
        try:
            expires_in = data.get("expires_in")
            if expires_in is not None:
                expires_in = int(expires_in)
            obtained_at = float(data.get("obtained_at", time.time()))
            expires_at = data.get("expires_at")
            if expires_at is not None:
                expires_at = float(expires_at)
            return cls(
                access_token=str(data["access_token"]),
                token_type=str(data.get("token_type", "Bearer")),
                refresh_token=(str(data["refresh_token"]) if data.get("refresh_token") else None),
                expires_in=expires_in,
                scope=(str(data["scope"]) if data.get("scope") else None),
                obtained_at=obtained_at,
                expires_at=expires_at,
            )
        except (TypeError, ValueError) as exc:
            raise InvalidTokenError(f"Malformed token data: {exc}") from exc


@dataclass(frozen=True)
class DeviceAuthorizationResponse:
    """Parsed response from the device authorization endpoint."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int = DEFAULT_POLL_INTERVAL
    verification_uri_complete: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeviceAuthorizationResponse:
        required = {"device_code", "user_code", "verification_uri", "expires_in"}
        # Google historically used verification_url; accept both.
        verification = data.get("verification_uri") or data.get("verification_url")
        if verification is None:
            raise OAuthError("Device response missing verification_uri / verification_url")
        missing = required - (set(data.keys()) | {"verification_url"})
        if "verification_uri" not in data and "verification_url" in data:
            missing.discard("verification_uri")
        if missing:
            raise OAuthError(f"Device response missing required fields: {sorted(missing)}")
        try:
            interval = int(data.get("interval", DEFAULT_POLL_INTERVAL))
            if interval < 1:
                interval = DEFAULT_POLL_INTERVAL
            return cls(
                device_code=str(data["device_code"]),
                user_code=str(data["user_code"]),
                verification_uri=str(verification),
                expires_in=int(data["expires_in"]),
                interval=interval,
                verification_uri_complete=(
                    str(data["verification_uri_complete"])
                    if data.get("verification_uri_complete")
                    else None
                ),
            )
        except (TypeError, ValueError) as exc:
            raise OAuthError(f"Malformed device authorization response: {exc}") from exc


# ---------------------------------------------------------------------------
# Transport abstraction (dependency injection)
# ---------------------------------------------------------------------------

class HttpTransport(Protocol):
    """Minimal HTTP transport protocol for dependency injection / testing."""

    def post_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        timeout: float,
    ) -> tuple[int, dict[str, Any]]:
        """POST application/x-www-form-urlencoded and return (status, json_body)."""
        ...


class UrllibTransport:
    """Default transport using stdlib urllib (no extra dependencies)."""

    def post_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        timeout: float,
    ) -> tuple[int, dict[str, Any]]:
        body = urllib.parse.urlencode(dict(data)).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", 200)
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read().decode("utf-8")
            except Exception:
                raw = ""
        except urllib.error.URLError as exc:
            raise OAuthNetworkError(f"Network error contacting {url}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise OAuthNetworkError(f"Timeout contacting {url}") from exc

        if not raw:
            return status, {}
        try:
            parsed: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OAuthError(
                f"Malformed JSON from {url} (HTTP {status})"
            ) from exc
        if not isinstance(parsed, dict):
            raise OAuthError(f"Expected JSON object from {url}, got {type(parsed).__name__}")
        return status, parsed


# ---------------------------------------------------------------------------
# Token storage
# ---------------------------------------------------------------------------

class TokenStore(Protocol):
    def load(self) -> OAuthToken | None: ...
    def save(self, token: OAuthToken) -> None: ...
    def invalidate(self) -> None: ...
    def inspect(self) -> dict[str, Any]: ...


class FileTokenStore:
    """Atomic, permission-restricted filesystem token store."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Restrict directory permissions where the platform supports it.
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    def load(self) -> OAuthToken | None:
        if not self.path.is_file():
            return None
        try:
            text = self.path.read_text(encoding="utf-8")
            data = json.loads(text)
            if not isinstance(data, dict):
                raise CorruptedCacheError("Cache root is not a JSON object")
            return OAuthToken.from_dict(data)
        except (OSError, json.JSONDecodeError, InvalidTokenError) as exc:
            raise CorruptedCacheError(f"Unable to load token cache: {exc}") from exc

    def save(self, token: OAuthToken) -> None:
        self._ensure_parent()
        payload = json.dumps(token.to_dict(), indent=2, sort_keys=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            tmp.write_text(payload, encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.replace(self.path)
        except OSError as exc:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            raise OAuthError(f"Failed to write token cache: {exc}") from exc

    def invalidate(self) -> None:
        try:
            if self.path.is_file():
                self.path.unlink()
        except OSError as exc:
            raise OAuthError(f"Failed to invalidate token cache: {exc}") from exc

    def inspect(self) -> dict[str, Any]:
        """Return non-secret metadata about the cache entry."""
        info: dict[str, Any] = {
            "path": str(self.path),
            "exists": self.path.is_file(),
        }
        if not info["exists"]:
            return info
        try:
            token = self.load()
        except CorruptedCacheError as exc:
            info["status"] = "corrupted"
            info["error"] = str(exc)
            return info
        if token is None:
            info["status"] = "empty"
            return info
        info["status"] = "present"
        info["token_type"] = token.token_type
        info["scope"] = token.scope
        info["has_refresh_token"] = bool(token.refresh_token)
        info["obtained_at"] = token.obtained_at
        info["expires_at"] = token.expires_at
        info["is_expired"] = token.is_expired()
        # Never include the actual token values.
        return info


def default_cache_path() -> Path:
    """Return a platform-appropriate cache path for OAuth tokens."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = Path.home() / ".cache"
    return base / CACHE_DIR_NAME / CACHE_FILENAME


# ---------------------------------------------------------------------------
# OAuth client & poller
# ---------------------------------------------------------------------------

class OAuthClient:
    """High-level OAuth 2.0 Device Authorization Grant client."""

    def __init__(
        self,
        config: OAuthConfig,
        *,
        transport: HttpTransport | None = None,
        token_store: TokenStore | None = None,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
        logger_: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.transport: HttpTransport = transport or UrllibTransport()
        self.token_store: TokenStore = token_store or FileTokenStore(default_cache_path())
        self.clock: Callable[[], float] = clock or time.time
        self.sleeper: Callable[[float], None] = sleeper or time.sleep
        self.log = logger_ or logger

    # ---- device authorization ------------------------------------------------

    def request_device_authorization(self) -> DeviceAuthorizationResponse:
        """POST to the device authorization endpoint and return the response."""
        form: dict[str, str] = {
            "client_id": self.config.client_id,
            "scope": self.config.scope,
        }
        if self.config.client_secret:
            form["client_secret"] = self.config.client_secret

        self.log.debug("Requesting device authorization code")
        try:
            status, body = self.transport.post_form(
                self.config.device_endpoint,
                form,
                timeout=self.config.timeout,
            )
        except OAuthNetworkError:
            raise
        except Exception as exc:
            raise OAuthNetworkError(f"Unexpected transport error: {exc}") from exc

        if status >= 400:
            self._raise_from_error_body(body, status, context="device authorization")

        return DeviceAuthorizationResponse.from_dict(body)

    def format_user_instructions(self, device: DeviceAuthorizationResponse) -> str:
        """Human-readable authorization message (never includes device_code)."""
        lines = [
            "To authorize this application, visit the following URL on any device:",
            "",
            f"  {device.verification_uri}",
            "",
            "and enter the code:",
            "",
            f"  {device.user_code}",
            "",
        ]
        if device.verification_uri_complete:
            lines.extend(
                [
                    "Or open this complete URL:",
                    "",
                    f"  {device.verification_uri_complete}",
                    "",
                ]
            )
        lines.append(
            f"The code expires in approximately {device.expires_in} seconds."
        )
        return "\n".join(lines)

    # ---- token polling -------------------------------------------------------

    def poll_for_token(
        self,
        device: DeviceAuthorizationResponse,
        *,
        cancel_check: Callable[[], bool] | None = None,
    ) -> OAuthToken:
        """Poll the token endpoint until authorization succeeds or fails.

        Respects RFC 8628 polling rules (interval, slow_down, expiry).
        ``cancel_check`` may return True to abort (e.g. on Ctrl+C).
        """
        interval = float(device.interval)
        deadline = self.clock() + float(device.expires_in)
        form: dict[str, str] = {
            "client_id": self.config.client_id,
            "device_code": device.device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }
        if self.config.client_secret:
            form["client_secret"] = self.config.client_secret

        while True:
            if cancel_check and cancel_check():
                raise OAuthError("Authorization cancelled by user")

            now = self.clock()
            if now >= deadline:
                raise AuthorizationExpiredError(
                    "Device authorization code expired before user completed the flow",
                    error_code="expired_token",
                )

            try:
                status, body = self.transport.post_form(
                    self.config.token_endpoint,
                    form,
                    timeout=self.config.timeout,
                )
            except OAuthNetworkError as exc:
                self.log.warning("Network error while polling token endpoint: %s", exc)
                # Back off on network errors instead of aggressive retry.
                self.sleeper(interval)
                interval = min(interval + SLOW_DOWN_INCREMENT, 60.0)
                continue

            error = body.get("error")
            if error is None and status < 400:
                token = self._token_from_response(body)
                self.token_store.save(token)
                self.log.info("OAuth authorization successful; token stored")
                return token

            if error == "authorization_pending":
                self.log.debug("Authorization still pending; sleeping %.1fs", interval)
                self.sleeper(interval)
                continue

            if error == "slow_down":
                interval += SLOW_DOWN_INCREMENT
                self.log.debug("Server requested slow_down; new interval=%.1fs", interval)
                self.sleeper(interval)
                continue

            if error == "access_denied":
                raise AuthorizationDeniedError(
                    "User denied the authorization request",
                    error_code="access_denied",
                )
            if error == "expired_token":
                raise AuthorizationExpiredError(
                    "Device code expired",
                    error_code="expired_token",
                )
            if error == "invalid_client":
                raise InvalidClientError(
                    "Client authentication failed (invalid_client)",
                    error_code="invalid_client",
                )
            if error == "invalid_grant":
                raise InvalidGrantError(
                    "Invalid grant (invalid_grant)",
                    error_code="invalid_grant",
                )
            if error == "invalid_request":
                raise InvalidRequestError(
                    "Invalid request (invalid_request)",
                    error_code="invalid_request",
                )
            if error == "unsupported_grant_type":
                raise UnsupportedGrantTypeError(
                    "Unsupported grant type",
                    error_code="unsupported_grant_type",
                )

            # Unknown error – surface a safe message without leaking secrets.
            raise OAuthError(
                f"Token endpoint returned error: {error or f'HTTP {status}'}",
                error_code=str(error) if error else None,
            )

    # ---- refresh -------------------------------------------------------------

    def refresh(self, token: OAuthToken) -> OAuthToken:
        """Exchange a refresh token for a new access token."""
        if not token.refresh_token:
            raise InvalidGrantError("No refresh_token available")
        form: dict[str, str] = {
            "client_id": self.config.client_id,
            "refresh_token": token.refresh_token,
            "grant_type": "refresh_token",
        }
        if self.config.client_secret:
            form["client_secret"] = self.config.client_secret

        self.log.debug("Refreshing OAuth access token")
        try:
            status, body = self.transport.post_form(
                self.config.token_endpoint,
                form,
                timeout=self.config.timeout,
            )
        except OAuthNetworkError:
            raise
        except Exception as exc:
            raise OAuthNetworkError(f"Unexpected transport error during refresh: {exc}") from exc

        if status >= 400:
            error = body.get("error")
            if error in ("invalid_grant", "invalid_token"):
                self.token_store.invalidate()
                raise InvalidGrantError(
                    "Refresh token rejected or revoked; cache invalidated",
                    error_code=str(error),
                )
            self._raise_from_error_body(body, status, context="token refresh")

        new_token = self._token_from_response(body, previous=token)
        self.token_store.save(new_token)
        self.log.info("OAuth access token refreshed successfully")
        return new_token

    def get_valid_token(self, *, force_refresh: bool = False) -> OAuthToken | None:
        """Load a cached token, refreshing if necessary.  Returns None if none available."""
        try:
            token = self.token_store.load()
        except CorruptedCacheError:
            self.log.warning("Token cache corrupted; invalidating")
            self.token_store.invalidate()
            return None
        if token is None:
            return None
        if force_refresh or token.is_expired(now=self.clock(), safety_margin=self.config.safety_margin):
            if not token.refresh_token:
                self.log.info("Access token expired and no refresh_token present")
                self.token_store.invalidate()
                return None
            try:
                return self.refresh(token)
            except (InvalidGrantError, OAuthNetworkError) as exc:
                self.log.warning("Token refresh failed: %s", exc)
                return None
        return token

    # ---- helpers -------------------------------------------------------------

    def _token_from_response(
        self,
        body: Mapping[str, Any],
        *,
        previous: OAuthToken | None = None,
    ) -> OAuthToken:
        if "access_token" not in body:
            raise InvalidTokenError("Token response missing access_token")
        refresh = body.get("refresh_token")
        if refresh is None and previous is not None:
            refresh = previous.refresh_token
        expires_in = body.get("expires_in")
        if expires_in is not None:
            try:
                expires_in = int(expires_in)
            except (TypeError, ValueError) as exc:
                raise InvalidTokenError(f"Invalid expires_in: {expires_in}") from exc
        return OAuthToken(
            access_token=str(body["access_token"]),
            token_type=str(body.get("token_type", "Bearer")),
            refresh_token=str(refresh) if refresh else None,
            expires_in=expires_in,
            scope=str(body["scope"]) if body.get("scope") else (previous.scope if previous else None),
            obtained_at=self.clock(),
        )

    def _raise_from_error_body(
        self,
        body: Mapping[str, Any],
        status: int,
        *,
        context: str,
    ) -> None:
        error = body.get("error")
        # Never include raw body in the message (may contain sensitive data).
        msg = f"{context} failed (HTTP {status})"
        if error == "invalid_client":
            raise InvalidClientError(msg, error_code="invalid_client")
        if error == "invalid_grant":
            raise InvalidGrantError(msg, error_code="invalid_grant")
        if error == "invalid_request":
            raise InvalidRequestError(msg, error_code="invalid_request")
        if error == "unsupported_grant_type":
            raise UnsupportedGrantTypeError(msg, error_code="unsupported_grant_type")
        raise OAuthError(msg, error_code=str(error) if error else None)


class OAuthPoller:
    """Thin convenience wrapper that runs the full device-flow interaction."""

    def __init__(self, client: OAuthClient) -> None:
        self.client = client

    def authorize(self, *, print_fn: Callable[[str], None] | None = None) -> OAuthToken:
        """Run device authorization + polling and return a token.

        ``print_fn`` defaults to ``print``.  Never prints the device_code.
        Handles KeyboardInterrupt cleanly.
        """
        printer = print_fn or print
        device = self.client.request_device_authorization()
        printer(self.client.format_user_instructions(device))
        printer("")
        printer("Waiting for authorization...")
        try:
            return self.client.poll_for_token(device)
        except KeyboardInterrupt:
            raise OAuthError("Authorization cancelled by user (KeyboardInterrupt)") from None


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def config_from_env() -> OAuthConfig:
    """Build an OAuthConfig from environment variables.

    Recognised variables:
      YTDLP_OAUTH_CLIENT_ID
      YTDLP_OAUTH_CLIENT_SECRET
      YTDLP_OAUTH_SCOPE
      YTDLP_OAUTH_DEVICE_ENDPOINT
      YTDLP_OAUTH_TOKEN_ENDPOINT
      YTDLP_OAUTH_TIMEOUT
      YTDLP_OAUTH_ALLOW_INSECURE
    """
    client_id = os.environ.get("YTDLP_OAUTH_CLIENT_ID", "").strip()
    if not client_id:
        raise ConfigurationError(
            "YTDLP_OAUTH_CLIENT_ID environment variable is required"
        )
    secret = os.environ.get("YTDLP_OAUTH_CLIENT_SECRET")
    scope = os.environ.get("YTDLP_OAUTH_SCOPE", DEFAULT_SCOPE)
    device_ep = os.environ.get("YTDLP_OAUTH_DEVICE_ENDPOINT", DEFAULT_DEVICE_ENDPOINT)
    token_ep = os.environ.get("YTDLP_OAUTH_TOKEN_ENDPOINT", DEFAULT_TOKEN_ENDPOINT)
    timeout_s = os.environ.get("YTDLP_OAUTH_TIMEOUT")
    timeout = float(timeout_s) if timeout_s else DEFAULT_TIMEOUT
    allow_insecure = os.environ.get("YTDLP_OAUTH_ALLOW_INSECURE", "").lower() in (
        "1",
        "true",
        "yes",
    )
    return OAuthConfig(
        client_id=client_id,
        client_secret=secret if secret else None,
        scope=scope,
        device_endpoint=device_ep,
        token_endpoint=token_ep,
        timeout=timeout,
        allow_insecure_endpoints=allow_insecure,
    )


def get_oauth_client(
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    cache_path: Path | str | None = None,
    **kwargs: Any,
) -> OAuthClient:
    """Convenience factory.

    If ``client_id`` is omitted, falls back to ``YTDLP_OAUTH_CLIENT_ID``.
    """
    if client_id is None:
        cfg = config_from_env()
    else:
        cfg = OAuthConfig(client_id=client_id, client_secret=client_secret, **kwargs)
    store = FileTokenStore(cache_path) if cache_path else None
    return OAuthClient(cfg, token_store=store)


# ---------------------------------------------------------------------------
# yt-dlp integration surface
# ---------------------------------------------------------------------------
# Current yt-dlp (post-2024.11) has removed YouTube OAuth support because
# YouTube-side changes made the obtained tokens unusable for Innertube.
# Consequently this plugin intentionally does NOT subclass or replace
# YoutubeIE.  Doing so would be misleading and could not restore
# functionality that YouTube itself has blocked.
#
# The OAuth engine above remains fully usable for:
# - research into the Device Authorization Grant,
# - testing OAuth client behaviour,
# - any future legitimate integration point that yt-dlp may expose.
#
# If you need authenticated YouTube access today, use cookie-based
# authentication as documented by yt-dlp.  PO Tokens are a completely
# separate subsystem; this plugin does not generate or claim to generate
# them.

def _check_ytdlp_compatibility() -> None:
    """Best-effort detection of yt-dlp presence / version.  Never raises on import."""
    try:
        import yt_dlp  # type: ignore[import-untyped]
        ver = getattr(yt_dlp, "version", None)
        if ver is not None:
            logger.debug("Detected yt-dlp version: %s", ver)
    except ImportError:
        logger.debug("yt-dlp not importable in this environment")


# Side-effect free import: only a debug log, no network, no auth prompts.
_check_ytdlp_compatibility()
