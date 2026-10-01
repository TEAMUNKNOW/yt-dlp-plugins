# yt-dlp-plugins — Complete Self-Contained Specification

> **Repository**: https://github.com/TEAMUNKNOW/yt-dlp-plugins  
> **Owner**: TEAMUNKNOW  
> **Version**: 0.1.0  
> **License**: MIT  
> **Python**: ≥ 3.10  
> **Runtime dependencies**: None (stdlib only)  
> **Purpose**: Standards-compliant OAuth 2.0 Device Authorization Grant (RFC 8628) engine packaged as a yt-dlp plugin for research / future integration.

---

## 1. Critical Current-State Limitation (Must Read First)

As of yt-dlp ≥ 2024.11.18:

- Official yt-dlp documentation states **YouTube OAuth login is no longer supported** because of YouTube-side restrictions.
- This repository implements Google’s Device Authorization protocol **correctly**.
- It does **NOT** claim that the resulting OAuth credentials will be accepted by YouTube Innertube.
- It does **NOT** generate PO Tokens.
- It does **NOT** bypass BotGuard, CAPTCHAs, IP blocks, age restrictions, or any security control.
- Implementing a clean OAuth client does **NOT** automatically restore YouTube authentication that YouTube itself has disabled.

**Practical consequence**: This plugin will **not** make age-restricted / members-only / high-rate YouTube downloads work via OAuth. Use cookies + PO Tokens for that.

---

## 2. Repository Structure

```
yt-dlp-plugins/
├── .gitignore
├── LICENSE                          # MIT
├── README.md
├── pyproject.toml                   # PEP 621 + hatchling + ruff/mypy/pytest
├── yt_dlp_plugins/
│   └── extractor/
│       └── youtube_oauth2.py        # ~880 lines – complete OAuth engine
└── tests/
    └── test_oauth2.py               # ~670 lines – fully mocked unit tests
```

No `__init__.py` files are required (yt-dlp uses namespace-package discovery).

---

## 3. Architecture Overview

| Component                        | Type              | Responsibility |
|----------------------------------|-------------------|----------------|
| `OAuthConfig`                    | frozen dataclass  | Immutable config (client_id, endpoints, timeouts, safety_margin) |
| `OAuthToken`                     | dataclass         | access_token, refresh_token, expires_at, is_expired() |
| `DeviceAuthorizationResponse`    | frozen dataclass  | device_code, user_code, verification_uri, interval, expires_in |
| `HttpTransport` (Protocol)       | Protocol          | `post_form(url, data, timeout) → (status, json)` |
| `UrllibTransport`                | concrete          | stdlib urllib implementation |
| `TokenStore` (Protocol)          | Protocol          | load / save / invalidate / inspect |
| `FileTokenStore`                 | concrete          | atomic JSON file + 0o600 / 0o700 permissions |
| `OAuthClient`                    | main class        | device request, polling, refresh, get_valid_token |
| `OAuthPoller`                    | convenience       | full interactive authorize() flow |
| Exception hierarchy              | 12 classes        | Precise, non-leaking errors |
| `redact_secrets()`               | utility           | Recursive secret redaction for safe logging |

**Dependency injection**: transport, clock, sleeper, token_store, logger are all injectable → 100 % unit-testable without contacting Google.

**Import is side-effect free**: no network, no auth prompts, no YoutubeIE monkey-patch.

---

## 4. Constants (never scattered)

```python
DEFAULT_DEVICE_ENDPOINT = "https://oauth2.googleapis.com/device/code"
DEFAULT_TOKEN_ENDPOINT  = "https://oauth2.googleapis.com/token"
DEFAULT_SCOPE           = "https://www.googleapis.com/auth/youtube"
DEFAULT_TIMEOUT         = 30.0
DEFAULT_SAFETY_MARGIN   = 60.0   # seconds before real expiry
DEFAULT_POLL_INTERVAL   = 5      # RFC 8628 default
SLOW_DOWN_INCREMENT     = 5      # RFC 8628 §3.5
CACHE_FILENAME          = "youtube_oauth2_token.json"
CACHE_DIR_NAME          = "yt-dlp-oauth2"
```

---

## 5. Exception Hierarchy

```
OAuthError
├── AuthorizationDeniedError      # access_denied
├── AuthorizationExpiredError     # expired_token / deadline
├── ExpiredTokenError
├── InvalidTokenError
├── OAuthNetworkError
├── InvalidClientError            # invalid_client
├── InvalidGrantError             # invalid_grant / revoked refresh
├── InvalidRequestError
├── UnsupportedGrantTypeError
├── CorruptedCacheError
├── IncompatibleYtDlpError
└── ConfigurationError            # missing client_id etc.
```

All exceptions accept optional `error_code`. Secrets are never placed in exception messages.

---

## 6. Core Data Models

### OAuthConfig (frozen)
- Required: `client_id` (non-empty)
- Optional: `client_secret`, `scope`, `device_endpoint`, `token_endpoint`, `timeout`, `safety_margin`
- `allow_insecure_endpoints=False` → rejects any non-HTTPS endpoint unless explicitly enabled (tests only)

### OAuthToken
- Fields: `access_token`, `token_type="Bearer"`, `refresh_token`, `expires_in`, `scope`, `obtained_at`, `expires_at`
- `is_expired(now=None, safety_margin=60)` – treats token as expired early by safety margin
- `to_dict()` / `from_dict()` with strict validation

### DeviceAuthorizationResponse
- Accepts both `verification_uri` and legacy `verification_url`
- Defaults `interval` to 5 if missing or < 1

---

## 7. OAuth Flow Implementation (RFC 8628)

### 7.1 Device Authorization Request
```python
POST device_endpoint
client_id=...&scope=...
(+ client_secret if present)
```
Returns `DeviceAuthorizationResponse`.

### 7.2 User-facing message
- Shows **only** `verification_uri` + `user_code` (+ complete URI if present)
- **Never** shows `device_code`

### 7.3 Polling (`poll_for_token`)
- Respects returned `interval`
- On `authorization_pending` → sleep(interval)
- On `slow_down` → interval += 5, then sleep
- On network error → backoff (interval increases, capped at 60 s)
- Stops when `clock() >= deadline` (device code expiry)
- Supports `cancel_check` callable (Ctrl+C path)
- Handles all standard errors: access_denied, expired_token, invalid_client, invalid_grant, invalid_request, unsupported_grant_type

### 7.4 Token Refresh
- Preserves existing `refresh_token` if server does not return a new one (rotation support)
- On `invalid_grant` → **atomically invalidates cache**
- Never loops prompting the user

### 7.5 `get_valid_token()`
1. Load from store
2. If corrupted → invalidate & return None
3. If expired (with safety margin) and has refresh_token → refresh
4. On refresh failure → return None (cache already cleared if invalid_grant)

---

## 8. Secure Token Storage (`FileTokenStore`)

- Default path: `$XDG_CACHE_HOME/yt-dlp-oauth2/youtube_oauth2_token.json` or `~/.cache/...`
- Atomic write: write to `.tmp` → `os.replace`
- Permissions: directory `0o700`, file `0o600` (best-effort)
- `inspect()` returns **non-secret** metadata only (`status`, `has_refresh_token`, `is_expired`, timestamps…)
- Corrupted / malformed JSON → `CorruptedCacheError`

---

## 9. Configuration Sources

| Source | Variables / Keys |
|--------|------------------|
| Environment | `YTDLP_OAUTH_CLIENT_ID` (required), `YTDLP_OAUTH_CLIENT_SECRET`, `YTDLP_OAUTH_SCOPE`, `YTDLP_OAUTH_DEVICE_ENDPOINT`, `YTDLP_OAUTH_TOKEN_ENDPOINT`, `YTDLP_OAUTH_TIMEOUT`, `YTDLP_OAUTH_ALLOW_INSECURE` |
| Explicit | `OAuthConfig(client_id=..., ...)` |
| Factory | `get_oauth_client(client_id=None, ...)` – falls back to env |

**No client secrets or “optimized YouTube scraping client IDs” are ever embedded.**

---

## 10. yt-dlp Integration Policy

- **Does NOT** subclass or replace `YoutubeIE`
- **Does NOT** monkey-patch anything
- **Does NOT** register any public `*IE` class
- Import is cheap and side-effect free
- Plugin is discovered under the official `yt_dlp_plugins` namespace package
- Normal yt-dlp operation continues even if this plugin is installed

Reason: YouTube itself rejects OAuth tokens for the previous use-cases. Faking an integration would be dishonest.

---

## 11. PO Token Separation

- OAuth tokens ≠ PO Tokens
- This project never generates, forges, or claims to generate PO Tokens
- Compatible with external PO Token providers (they are completely orthogonal)

---

## 12. Security Model

- No hardcoded secrets
- Secrets never appear in logs, exception strings, or debug output
- `redact_secrets()` recursively replaces `access_token`, `refresh_token`, `device_code`, `client_secret`, `id_token`
- HTTPS required by default
- TLS verification never disabled
- JSON structure validated
- No CAPTCHA / IP-block / age-restriction / bot-detection bypass code of any kind

---

## 13. Testing Strategy

- **Zero network calls** – all tests use `FakeTransport` + `FakeClock` + injectable sleeper
- Coverage includes:
  - successful device auth + polling
  - authorization_pending → success
  - slow_down (interval increases by ≥ 5)
  - access_denied, expired_token, invalid_client, invalid_grant
  - network timeout + backoff
  - cancel_check / KeyboardInterrupt
  - access-token expiry + safety margin
  - refresh success + refresh-token rotation + preservation
  - invalid refresh → cache invalidation
  - corrupted cache detection
  - atomic write
  - missing client_id / insecure endpoint rejection
  - secret redaction
  - env-config helpers

Run with:
```bash
pytest
ruff check .
mypy yt_dlp_plugins
```

---

## 14. pyproject.toml Highlights

- Build backend: hatchling
- `requires-python = ">=3.10"`
- Zero runtime dependencies
- Optional `dev` extra: pytest, ruff, mypy, pytest-cov
- Strict mypy + ruff configuration
- Package discovery: `yt_dlp_plugins` (namespace package friendly)

---

## 15. Public API Surface (`__all__`)

```python
OAuthConfig, OAuthToken, DeviceAuthorizationResponse,
OAuthClient, OAuthPoller,
TokenStore, FileTokenStore,
OAuthError, AuthorizationDeniedError, AuthorizationExpiredError,
ExpiredTokenError, InvalidTokenError, OAuthNetworkError,
InvalidClientError, InvalidGrantError, InvalidRequestError,
UnsupportedGrantTypeError, CorruptedCacheError,
IncompatibleYtDlpError, ConfigurationError,
redact_secrets, get_oauth_client
```

---

## 16. Typical Usage (Programmatic)

```python
from yt_dlp_plugins.extractor.youtube_oauth2 import (
    OAuthConfig, OAuthClient, OAuthPoller
)

config = OAuthConfig(client_id="YOUR_CLIENT_ID")
client = OAuthClient(config)
poller = OAuthPoller(client)

token = poller.authorize()          # prints URL + user_code, polls
# or
token = client.get_valid_token()    # load / refresh from cache
```

---

## 17. What This Repo Is / Is Not

| Is | Is Not |
|----|--------|
| Clean RFC 8628 Device Flow implementation | YouTube anti-bot solution |
| Fully tested, typed, injectable OAuth engine | PO Token generator |
| Research / future-integration foundation | Drop-in YoutubeIE replacement |
| Honest about current YouTube limitations | Claim of “guaranteed no CAPTCHA” or “undetectable” |

---

## 18. Compatibility Policy

- Targets current stable yt-dlp plugin architecture (namespace package)
- Does not claim “works with all future yt-dlp versions”
- If yt-dlp later re-introduces a legitimate OAuth hook, a thin compatibility layer can be added without changing the core engine
- Python 3.10+ (follows yt-dlp’s own support window)

---

## 19. File-level Summary for AI Ingestion

- **youtube_oauth2.py** (~32 KB): complete production-quality OAuth engine with all classes listed above. No private yt-dlp imports. No network on import.
- **test_oauth2.py** (~19 KB): exhaustive mocked tests covering every error path, polling rule, refresh rotation, cache corruption, and redaction.
- **pyproject.toml**: modern packaging, zero runtime deps, strict lint/type config.
- **README.md**: user-facing documentation that never hides the YouTube limitation.

---

## 20. One-sentence Summary for Other AIs

This is a **standards-compliant, fully-tested, zero-dependency OAuth 2.0 Device Authorization Grant (RFC 8628) client** packaged as a yt-dlp plugin for research purposes; it deliberately does **not** override YoutubeIE and does **not** claim to restore YouTube OAuth authentication that YouTube itself disabled in 2024.
