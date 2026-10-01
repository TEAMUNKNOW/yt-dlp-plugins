"""Unit tests for the OAuth 2.0 Device Authorization Grant engine.

All network interaction is mocked.  No real Google endpoints or credentials
are contacted.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Mapping
from unittest.mock import MagicMock

import pytest

from yt_dlp_plugins.extractor.youtube_oauth2 import (
    AuthorizationDeniedError,
    AuthorizationExpiredError,
    ConfigurationError,
    CorruptedCacheError,
    DeviceAuthorizationResponse,
    FileTokenStore,
    InvalidClientError,
    InvalidGrantError,
    InvalidTokenError,
    OAuthClient,
    OAuthConfig,
    OAuthError,
    OAuthNetworkError,
    OAuthPoller,
    OAuthToken,
    UrllibTransport,
    config_from_env,
    redact_secrets,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

class FakeTransport:
    """Deterministic HTTP transport for tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, str]]] = []
        self._handlers: list[Callable[[str, Mapping[str, str]], tuple[int, dict[str, Any]]]] = []

    def queue(self, status: int, body: dict[str, Any]) -> None:
        self._handlers.append(lambda url, data: (status, body))

    def queue_error(self, exc: Exception) -> None:
        def _raise(url: str, data: Mapping[str, str]) -> tuple[int, dict[str, Any]]:
            raise exc
        self._handlers.append(_raise)

    def post_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        timeout: float,
    ) -> tuple[int, dict[str, Any]]:
        self.calls.append((url, dict(data)))
        if not self._handlers:
            raise AssertionError("No more queued responses")
        handler = self._handlers.pop(0)
        return handler(url, data)


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def config() -> OAuthConfig:
    return OAuthConfig(
        client_id="test-client-id",
        client_secret=None,
        allow_insecure_endpoints=True,
        device_endpoint="https://example.test/device",
        token_endpoint="https://example.test/token",
    )


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def sleeper() -> list[float]:
    sleeps: list[float] = []

    def _sleep(seconds: float) -> None:
        sleeps.append(seconds)

    return sleeps  # type: ignore[return-value]


def make_client(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    sleeper_list: list[float],
    tmp_path: Path,
) -> OAuthClient:
    store = FileTokenStore(tmp_path / "token.json")

    def _sleep(s: float) -> None:
        sleeper_list.append(s)
        clock.advance(s)

    return OAuthClient(
        config,
        transport=transport,
        token_store=store,
        clock=clock,
        sleeper=_sleep,
    )


# ---------------------------------------------------------------------------
# OAuthConfig
# ---------------------------------------------------------------------------

def test_config_requires_client_id() -> None:
    with pytest.raises(ConfigurationError):
        OAuthConfig(client_id="")


def test_config_rejects_insecure_endpoints() -> None:
    with pytest.raises(ConfigurationError, match="Insecure endpoint"):
        OAuthConfig(
            client_id="cid",
            device_endpoint="http://insecure.example/device",
        )


def test_config_allows_insecure_when_flag_set() -> None:
    cfg = OAuthConfig(
        client_id="cid",
        device_endpoint="http://localhost/device",
        token_endpoint="http://localhost/token",
        allow_insecure_endpoints=True,
    )
    assert cfg.device_endpoint.startswith("http://")


# ---------------------------------------------------------------------------
# DeviceAuthorizationResponse
# ---------------------------------------------------------------------------

def test_device_response_happy_path() -> None:
    data = {
        "device_code": "dc-secret",
        "user_code": "ABCD-1234",
        "verification_uri": "https://google.com/device",
        "expires_in": 1800,
        "interval": 5,
    }
    resp = DeviceAuthorizationResponse.from_dict(data)
    assert resp.user_code == "ABCD-1234"
    assert resp.device_code == "dc-secret"
    assert resp.interval == 5


def test_device_response_accepts_verification_url() -> None:
    data = {
        "device_code": "dc",
        "user_code": "CODE",
        "verification_url": "https://google.com/device",
        "expires_in": 600,
    }
    resp = DeviceAuthorizationResponse.from_dict(data)
    assert resp.verification_uri == "https://google.com/device"


def test_device_response_missing_fields() -> None:
    with pytest.raises(OAuthError, match="missing required"):
        DeviceAuthorizationResponse.from_dict({"device_code": "x"})


def test_device_response_malformed_expires() -> None:
    with pytest.raises(OAuthError, match="Malformed"):
        DeviceAuthorizationResponse.from_dict(
            {
                "device_code": "dc",
                "user_code": "uc",
                "verification_uri": "https://x",
                "expires_in": "not-an-int",
            }
        )


# ---------------------------------------------------------------------------
# OAuthToken
# ---------------------------------------------------------------------------

def test_token_expiry_calculation() -> None:
    tok = OAuthToken(
        access_token="at",
        expires_in=3600,
        obtained_at=1_000_000.0,
    )
    assert tok.expires_at == 1_003_600.0
    assert not tok.is_expired(now=1_000_100.0, safety_margin=60)
    assert tok.is_expired(now=1_003_550.0, safety_margin=60)


def test_token_from_dict_roundtrip() -> None:
    original = OAuthToken(
        access_token="access",
        refresh_token="refresh",
        expires_in=3600,
        scope="https://www.googleapis.com/auth/youtube",
        obtained_at=1_000_000.0,
    )
    restored = OAuthToken.from_dict(original.to_dict())
    assert restored.access_token == "access"
    assert restored.refresh_token == "refresh"
    assert restored.expires_at == original.expires_at


def test_token_from_dict_missing_access() -> None:
    with pytest.raises(InvalidTokenError):
        OAuthToken.from_dict({"refresh_token": "r"})


# ---------------------------------------------------------------------------
# redact_secrets
# ---------------------------------------------------------------------------

def test_redact_secrets() -> None:
    data = {
        "access_token": "secret-at",
        "refresh_token": "secret-rt",
        "device_code": "secret-dc",
        "user_code": "ABCD",
        "nested": {"client_secret": "cs", "ok": 1},
    }
    redacted = redact_secrets(data)
    assert redacted["access_token"] == "***REDACTED***"
    assert redacted["refresh_token"] == "***REDACTED***"
    assert redacted["device_code"] == "***REDACTED***"
    assert redacted["user_code"] == "ABCD"
    assert redacted["nested"]["client_secret"] == "***REDACTED***"
    assert redacted["nested"]["ok"] == 1


# ---------------------------------------------------------------------------
# FileTokenStore
# ---------------------------------------------------------------------------

def test_file_store_atomic_roundtrip(tmp_path: Path) -> None:
    store = FileTokenStore(tmp_path / "tok.json")
    assert store.load() is None
    tok = OAuthToken(access_token="a", refresh_token="r", expires_in=100)
    store.save(tok)
    loaded = store.load()
    assert loaded is not None
    assert loaded.access_token == "a"
    assert loaded.refresh_token == "r"
    info = store.inspect()
    assert info["status"] == "present"
    assert "access_token" not in info
    store.invalidate()
    assert store.load() is None


def test_file_store_corrupted(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    store = FileTokenStore(path)
    with pytest.raises(CorruptedCacheError):
        store.load()
    info = store.inspect()
    assert info["status"] == "corrupted"


# ---------------------------------------------------------------------------
# Device authorization request
# ---------------------------------------------------------------------------

def test_request_device_authorization_success(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    transport.queue(
        200,
        {
            "device_code": "dc",
            "user_code": "USER-CODE",
            "verification_uri": "https://google.com/device",
            "expires_in": 1800,
            "interval": 5,
        },
    )
    client = make_client(config, transport, clock, [], tmp_path)
    device = client.request_device_authorization()
    assert device.user_code == "USER-CODE"
    assert len(transport.calls) == 1
    assert transport.calls[0][1]["client_id"] == "test-client-id"
    # device_code must never appear in user-facing text
    msg = client.format_user_instructions(device)
    assert "dc" not in msg
    assert "USER-CODE" in msg
    assert "https://google.com/device" in msg


def test_request_device_authorization_invalid_client(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    transport.queue(401, {"error": "invalid_client"})
    client = make_client(config, transport, clock, [], tmp_path)
    with pytest.raises(InvalidClientError):
        client.request_device_authorization()


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------

def test_poll_authorization_pending_then_success(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    sleeps: list[float] = []
    client = make_client(config, transport, clock, sleeps, tmp_path)
    device = DeviceAuthorizationResponse(
        device_code="dc",
        user_code="UC",
        verification_uri="https://ex",
        expires_in=600,
        interval=5,
    )
    transport.queue(400, {"error": "authorization_pending"})
    transport.queue(
        200,
        {
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt-1",
            "scope": config.scope,
        },
    )
    token = client.poll_for_token(device)
    assert token.access_token == "at-1"
    assert token.refresh_token == "rt-1"
    assert sleeps == [5.0]


def test_poll_slow_down(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    sleeps: list[float] = []
    client = make_client(config, transport, clock, sleeps, tmp_path)
    device = DeviceAuthorizationResponse(
        device_code="dc",
        user_code="UC",
        verification_uri="https://ex",
        expires_in=600,
        interval=5,
    )
    transport.queue(400, {"error": "slow_down"})
    transport.queue(
        200,
        {"access_token": "at", "expires_in": 3600, "refresh_token": "rt"},
    )
    token = client.poll_for_token(device)
    assert token.access_token == "at"
    # first sleep uses original interval; after slow_down the next sleep is 10
    assert sleeps[0] == 10.0


def test_poll_access_denied(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    device = DeviceAuthorizationResponse(
        device_code="dc",
        user_code="UC",
        verification_uri="https://ex",
        expires_in=600,
        interval=5,
    )
    transport.queue(400, {"error": "access_denied"})
    with pytest.raises(AuthorizationDeniedError):
        client.poll_for_token(device)


def test_poll_expired_token(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    device = DeviceAuthorizationResponse(
        device_code="dc",
        user_code="UC",
        verification_uri="https://ex",
        expires_in=600,
        interval=5,
    )
    transport.queue(400, {"error": "expired_token"})
    with pytest.raises(AuthorizationExpiredError):
        client.poll_for_token(device)


def test_poll_deadline_exceeded(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    sleeps: list[float] = []
    client = make_client(config, transport, clock, sleeps, tmp_path)
    device = DeviceAuthorizationResponse(
        device_code="dc",
        user_code="UC",
        verification_uri="https://ex",
        expires_in=10,
        interval=5,
    )
    # Advance clock past expiry before any poll.
    clock.advance(11)
    with pytest.raises(AuthorizationExpiredError):
        client.poll_for_token(device)


def test_poll_network_timeout_backoff(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    sleeps: list[float] = []
    client = make_client(config, transport, clock, sleeps, tmp_path)
    device = DeviceAuthorizationResponse(
        device_code="dc",
        user_code="UC",
        verification_uri="https://ex",
        expires_in=600,
        interval=5,
    )
    transport.queue_error(OAuthNetworkError("timeout"))
    transport.queue(
        200,
        {"access_token": "at", "expires_in": 3600, "refresh_token": "rt"},
    )
    token = client.poll_for_token(device)
    assert token.access_token == "at"
    assert sleeps[0] == 5.0


def test_poll_cancel_check(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    device = DeviceAuthorizationResponse(
        device_code="dc",
        user_code="UC",
        verification_uri="https://ex",
        expires_in=600,
        interval=5,
    )
    with pytest.raises(OAuthError, match="cancelled"):
        client.poll_for_token(device, cancel_check=lambda: True)


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

def test_refresh_success_preserves_refresh_token(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    old = OAuthToken(
        access_token="old-at",
        refresh_token="rt-keep",
        expires_in=10,
        obtained_at=clock.now,
    )
    transport.queue(
        200,
        {
            "access_token": "new-at",
            "expires_in": 3600,
            # no refresh_token in response → keep previous
        },
    )
    new = client.refresh(old)
    assert new.access_token == "new-at"
    assert new.refresh_token == "rt-keep"


def test_refresh_rotation(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    old = OAuthToken(access_token="old", refresh_token="old-rt", expires_in=10)
    transport.queue(
        200,
        {
            "access_token": "new",
            "refresh_token": "new-rt",
            "expires_in": 3600,
        },
    )
    new = client.refresh(old)
    assert new.refresh_token == "new-rt"


def test_refresh_invalid_grant_invalidates_cache(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    old = OAuthToken(access_token="old", refresh_token="rt", expires_in=10)
    client.token_store.save(old)
    transport.queue(400, {"error": "invalid_grant"})
    with pytest.raises(InvalidGrantError):
        client.refresh(old)
    assert client.token_store.load() is None


def test_get_valid_token_refresh_path(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    expired = OAuthToken(
        access_token="old",
        refresh_token="rt",
        expires_in=1,
        obtained_at=clock.now - 100,
    )
    client.token_store.save(expired)
    transport.queue(
        200,
        {"access_token": "fresh", "expires_in": 3600, "refresh_token": "rt"},
    )
    tok = client.get_valid_token()
    assert tok is not None
    assert tok.access_token == "fresh"


# ---------------------------------------------------------------------------
# OAuthPoller
# ---------------------------------------------------------------------------

def test_poller_full_flow(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    transport.queue(
        200,
        {
            "device_code": "dc",
            "user_code": "UC",
            "verification_uri": "https://ex",
            "expires_in": 600,
            "interval": 1,
        },
    )
    transport.queue(
        200,
        {"access_token": "at", "expires_in": 3600, "refresh_token": "rt"},
    )
    printed: list[str] = []
    poller = OAuthPoller(client)
    token = poller.authorize(print_fn=printed.append)
    assert token.access_token == "at"
    assert any("UC" in line for line in printed)


# ---------------------------------------------------------------------------
# Environment config
# ---------------------------------------------------------------------------

def test_config_from_env_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("YTDLP_OAUTH_CLIENT_ID", raising=False)
    with pytest.raises(ConfigurationError):
        config_from_env()


def test_config_from_env_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YTDLP_OAUTH_CLIENT_ID", "env-cid")
    monkeypatch.setenv("YTDLP_OAUTH_SCOPE", "scope-x")
    cfg = config_from_env()
    assert cfg.client_id == "env-cid"
    assert cfg.scope == "scope-x"


# ---------------------------------------------------------------------------
# KeyboardInterrupt path (poller)
# ---------------------------------------------------------------------------

def test_poller_keyboard_interrupt(
    config: OAuthConfig,
    transport: FakeTransport,
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    client = make_client(config, transport, clock, [], tmp_path)
    transport.queue(
        200,
        {
            "device_code": "dc",
            "user_code": "UC",
            "verification_uri": "https://ex",
            "expires_in": 600,
            "interval": 5,
        },
    )

    def boom() -> DeviceAuthorizationResponse:
        raise KeyboardInterrupt

    client.request_device_authorization = boom  # type: ignore[method-assign]
    poller = OAuthPoller(client)
    with pytest.raises(OAuthError, match="cancelled"):
        poller.authorize(print_fn=lambda _: None)
