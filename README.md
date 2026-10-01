# yt-dlp-plugins

**Standards-compliant OAuth 2.0 Device Authorization Grant (RFC 8628) engine packaged as a yt-dlp plugin.**

> **Critical limitation (current as of yt-dlp ≥ 2024.11.18)**  
> Official yt-dlp documentation states that **YouTube OAuth login is no longer supported** because of YouTube-side restrictions.  
> This project implements Google’s Device Authorization protocol correctly.  
> It does **not** claim that the resulting OAuth credentials will be accepted by YouTube Innertube, will generate PO Tokens, will bypass BotGuard, CAPTCHAs, IP blocks, age restrictions, or any other security control.  
> Implementing a clean OAuth client does **not** automatically restore YouTube authentication that YouTube itself has disabled.

---

## Purpose

- Provide a modern, maintainable, fully-tested OAuth 2.0 Device Authorization Grant client.
- Follow the current yt-dlp plugin architecture (namespace package `yt_dlp_plugins`).
- Serve as a research / integration reference for standards-compliant device-flow OAuth.
- Remain honest about the separation between:
  1. Google’s OAuth Device Authorization protocol
  2. yt-dlp authentication / cookie handling
  3. YouTube Innertube authentication
  4. YouTube PO Tokens / BotGuard attestation
  5. yt-dlp’s current plugin APIs

## Architecture

| Component              | Responsibility                                      |
|------------------------|-----------------------------------------------------|
| `OAuthConfig`          | Immutable configuration (endpoints, client id, …)  |
| `OAuthToken`           | Strongly-typed token model with expiry logic        |
| `DeviceAuthorizationResponse` | Parsed device-code response                   |
| `OAuthClient`          | Device request, polling, refresh, cache interaction |
| `OAuthPoller`          | Convenience wrapper for the full interactive flow   |
| `FileTokenStore`       | Atomic, permission-restricted filesystem cache      |
| Exception hierarchy    | Precise, non-leaking error types                    |
| `redact_secrets`       | Safe logging helper                                 |

All network, clock, sleep, and storage dependencies are injectable, making the flow unit-testable without contacting Google.

## Requirements

- Python **3.10+**
- Current stable yt-dlp (plugin discovery works with the official namespace-package layout)
- No runtime dependencies beyond the Python standard library

## Installation

### From the repository (recommended while the package is not on PyPI)

```bash
python -m pip install -U "git+https://github.com/TEAMUNKNOW/yt-dlp-plugins.git"
```

Or with pipx (inject into an existing yt-dlp environment):

```bash
pipx inject yt-dlp "git+https://github.com/TEAMUNKNOW/yt-dlp-plugins.git"
```

### Manual / development

```bash
git clone https://github.com/TEAMUNKNOW/yt-dlp-plugins.git
cd yt-dlp-plugins
python -m pip install -e ".[dev]"
```

After installation, run yt-dlp with `-v` and look for the plugin being discovered under `yt_dlp_plugins`.  
Because this plugin intentionally does **not** replace `YoutubeIE`, you will not see an extractor override; the OAuth engine is available for programmatic use.

## Configuration

| Environment variable              | Meaning                                      | Default                                      |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| `YTDLP_OAUTH_CLIENT_ID`           | Google OAuth client ID (required)            | —                                            |
| `YTDLP_OAUTH_CLIENT_SECRET`       | Client secret (optional for many client types)| —                                            |
| `YTDLP_OAUTH_SCOPE`               | OAuth scope                                  | `https://www.googleapis.com/auth/youtube`    |
| `YTDLP_OAUTH_DEVICE_ENDPOINT`     | Device authorization endpoint                | `https://oauth2.googleapis.com/device/code`  |
| `YTDLP_OAUTH_TOKEN_ENDPOINT`      | Token endpoint                               | `https://oauth2.googleapis.com/token`        |
| `YTDLP_OAUTH_TIMEOUT`             | HTTP timeout (seconds)                       | `30`                                         |
| `YTDLP_OAUTH_ALLOW_INSECURE`      | Allow `http://` endpoints (tests only)       | unset / false                                |

Never embed client secrets or “scraping-optimized” client IDs in source, README examples, or git history.

## Google Cloud setup (high-level)

1. Create a project in Google Cloud Console.
2. Enable the YouTube Data API (or the APIs required by your chosen scope).
3. Create an OAuth 2.0 Client ID of a type that supports the Device Authorization Grant (commonly “TVs and Limited Input devices” or equivalent).
4. Copy the client ID (and secret if issued).
5. Set `YTDLP_OAUTH_CLIENT_ID` (and optionally `YTDLP_OAUTH_CLIENT_SECRET`).

This project never hard-codes any Google client credentials.

## Device authorization walkthrough

```python
from yt_dlp_plugins.extractor.youtube_oauth2 import (
    OAuthConfig,
    OAuthClient,
    OAuthPoller,
    FileTokenStore,
)

config = OAuthConfig(client_id="YOUR_CLIENT_ID")
client = OAuthClient(config)
poller = OAuthPoller(client)

# Interactive: prints verification URL + user_code, then polls.
token = poller.authorize()
print("Got access token (length):", len(token.access_token))
```

The printed message never contains the `device_code`.  
Polling respects `interval`, `slow_down`, and the device-code expiry (RFC 8628).

## Token storage & refresh

- Tokens are stored under a platform cache directory (`$XDG_CACHE_HOME/yt-dlp-oauth2/` or `~/.cache/yt-dlp-oauth2/`).
- Writes are atomic (temp file + rename).
- Permissions are restricted to the owner where the OS allows it.
- Before use, `get_valid_token()` checks expiry (with a configurable safety margin) and refreshes when possible.
- If a refresh fails with `invalid_grant`, the cache is invalidated and a clear error is raised.
- Rotated refresh tokens are handled correctly; if the server omits a new refresh token the previous one is preserved.

Inspect the cache without revealing secrets:

```python
store = FileTokenStore(...)  # or client.token_store
print(store.inspect())
# → {'path': '...', 'status': 'present', 'has_refresh_token': True, 'is_expired': False, ...}
```

## yt-dlp integration

This plugin **does not** monkey-patch or subclass `YoutubeIE`.  
Current yt-dlp removed YouTube OAuth support; inventing a replacement hook would be misleading and would not restore functionality that YouTube has blocked.

The OAuth engine is importable and usable from any Python code that needs a clean Device Authorization Grant client.  
Should a future, officially supported yt-dlp integration point appear, a thin compatibility layer can be added without changing the core engine.

Normal yt-dlp operation is completely unaffected by the presence of this plugin.

## PO Token separation

**OAuth tokens ≠ PO Tokens.**

- This project does not generate, forge, or claim to generate PO Tokens.
- It does not interact with BotGuard attestation.
- It is compatible with external PO Token providers (e.g. the community PO Token Framework) because it does not interfere with them.

Refer to the [yt-dlp PO Token Guide](https://github.com/yt-dlp/yt-dlp/wiki/PO-Token-Guide) for the current recommended approach to PO Tokens.

## Security model

- No hardcoded client secrets.
- Secrets are never logged, never placed in exception messages, never written to debug output.
- HTTPS endpoints are required by default.
- TLS verification is never disabled.
- JSON responses are validated before use.
- Corrupted caches are detected and rejected.
- The plugin performs **no** CAPTCHA bypass, IP-block bypass, age-restriction bypass, or bot-detection evasion.

## Troubleshooting

| Symptom                         | Likely cause / action                                      |
|---------------------------------|------------------------------------------------------------|
| `ConfigurationError`            | `YTDLP_OAUTH_CLIENT_ID` not set                            |
| `InvalidClientError`            | Wrong client ID / type not allowed for device flow         |
| `AuthorizationDeniedError`      | User clicked “Deny” on the consent screen                  |
| `AuthorizationExpiredError`     | User took too long; restart the flow                       |
| `InvalidGrantError` on refresh  | Refresh token revoked; cache cleared, re-authorize         |
| `CorruptedCacheError`           | Delete the cache file and re-authorize                     |
| Network timeouts                | Automatic backoff; check connectivity / firewall           |

Run with increased logging:

```python
import logging
logging.getLogger("yt_dlp_plugins.extractor.youtube_oauth2").setLevel(logging.DEBUG)
```

## Privacy considerations

- Tokens are stored only on the local machine under the user’s cache directory.
- No telemetry, no phoning-home, no external analytics.
- Users should treat OAuth tokens with the same care as passwords and respect Google’s and YouTube’s terms of service and applicable law.

## Supported platforms & Python versions

- Linux, macOS, Windows
- Python 3.10, 3.11, 3.12, 3.13
- Compatibility follows yt-dlp’s own Python support window (3.10 is currently still supported; expect it to be dropped after its upstream EOL).

## Compatibility policy

- The OAuth engine targets RFC 8628 and Google’s public device endpoints.
- The yt-dlp integration surface is intentionally minimal and side-effect-free on import.
- We do not claim “works with all future yt-dlp versions.”
- When yt-dlp changes its plugin or authentication APIs we will adapt or clearly document the new limitation.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy yt_dlp_plugins
```

All tests mock the HTTP transport; they never contact Google or use real credentials.

## Known limitations

1. YouTube currently rejects OAuth-based authentication for the use-cases yt-dlp previously supported.
2. No public IE replacement is provided; the module is a pure OAuth engine + research plugin.
3. Client IDs must be supplied by the user; none are embedded.
4. PO Token generation is out of scope.

## FAQ

**Q: Will this let me download age-restricted or members-only YouTube videos again?**  
A: No. YouTube-side changes made OAuth unusable for that purpose. Use cookies (and, where required, PO Tokens) as documented by yt-dlp.

**Q: Does this generate PO Tokens?**  
A: No.

**Q: Can I use a “TV” client ID to avoid bot detection?**  
A: This project makes no claims about bot detection, scraping, or bypass techniques. Supply your own legitimate client credentials.

**Q: Why ship a plugin that doesn’t restore YouTube login?**  
A: Because a correct, tested, standards-compliant Device Authorization Grant implementation remains useful for research, for other Google APIs that still accept the flow, and as a clean foundation if a legitimate integration path reappears.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

- [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) and its plugin architecture
- The broader yt-dlp community for documenting the current state of YouTube authentication and PO Tokens
