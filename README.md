# Codex OAuth

Sample implementation of OAuth access to OpenAI's **WHAM** backend using the
`openai-python` library.

**WHAM** (Workspace-Handled Agent Model) is an internal backend used by the Codex CLI,
available at `https://chatgpt.com/backend-api/wham`. It requires OAuth tokens rather than
standard API keys and uses an API surface that differs from the public Chat Completions API.
A ChatGPT **Pro or Plus** account is required (subject to change).

The sample implementation is in `codex_oauth.py`.

> **Note**: The API behavior documented here was reverse-engineered from the
> [Codex CLI](https://github.com/openai/codex) and [OpenCode](https://github.com/anomalyco/opencode)
> source code and is not officially documented by OpenAI.
>
> **Warning**: As of the time this repository was created, OpenAI does not explicitly
> prohibit third-party OAuth usage with these credentials, but this may change at any time.
> **USE AT YOUR OWN RISK.**

## Requirements

- Python 3.13+
- ChatGPT Pro or Plus account

Dependencies (`pyproject.toml`):

```toml
dependencies = [
    "authlib>=1.6.8",
    "openai>=2.21.0",
]
```

`httpx` is used at runtime for token refresh and is pulled in as a transitive dependency.

## Setup & Usage

```bash
uv sync

uv run codex_oauth.py login           # browser OAuth, saves auth.json
uv run codex_oauth.py test            # connection test
uv run codex_oauth.py test -m <slug>  # specify model
uv run codex_oauth.py list            # fetch available models, saves models.json
```

The `test` and `list` commands automatically refresh the OAuth token before making API requests if it is expired or near expiry.

## WHAM API Specifics

### Endpoints & Constants

| Constant | Value |
|---|---|
| `AUTH_URL` | `https://auth.openai.com/oauth/authorize` |
| `TOKEN_URL` | `https://auth.openai.com/oauth/token` |
| `BASE_URL` | `https://chatgpt.com/backend-api/wham` |
| `CLIENT_ID` | `app_EMoamEEZ73f0CkXaXp7hrann` |
| `SCOPE` | `openid profile email offline_access` |
| `REDIRECT_URI` | `http://localhost:1455/auth/callback` |

`CLIENT_ID` is the Codex CLI's client ID, also reused by OpenCode. No standard allocation
mechanism exists for third-party apps.

`SCOPE` and `REDIRECT_URI` are only needed during login, so they are defined locally inside
`cmd_login` rather than at module level.

### OAuth Login

**PKCE**: authlib's `OAuth2Client` does not auto-add `code_challenge` even when
`code_challenge_method="S256"` is passed to the constructor — generate it manually using
`secrets` and `hashlib`.

**Authorization URL**: three OpenAI-specific parameters are required in
`create_authorization_url()`:

```python
id_token_add_organizations="true"
codex_cli_simplified_flow="true"
originator="opencode"
```

**Token exchange**: authlib automatically adds `grant_type`, `client_id`, and `redirect_uri`
to the `fetch_token` request; `code_verifier` must be passed explicitly.

### AuthManager

**`auth.json` schema:**

```json
{
  "type":      "oauth",
  "access":    "<access_token>",
  "refresh":   "<refresh_token>",
  "expires":   1234567890000,
  "accountId": "<chatgpt_account_id>"
}
```

`expires` is a Unix timestamp in **milliseconds**. `accountId` is omitted when it cannot
be extracted.

**`account_id` extraction**: decoded from the JWT payload (no signature verification
needed). Uses a 3-level fallback tried on `id_token` first, then `access_token`:

1. Top-level `chatgpt_account_id`
2. `https://api.openai.com/auth` → `chatgpt_account_id`
3. `organizations[0].id`

**`make_client()`**: the OAuth access token is passed as `api_key`; the openai library
formats it as `Authorization: Bearer <token>`. The `ChatGPT-Account-Id` header is required
when `accountId` is available.

**Token refresh**: `SAFETY_MARGIN = 30` seconds — `ensure_valid()` triggers a refresh when
fewer than 30 s remain before expiry. `auto_refresh(f, ...)` pre-checks validity, calls
`f(self, ...)`, and retries once on HTTP 401. `f` receives the `AuthManager` instance as
its first argument so it can call `make_client()` with the updated token after a refresh.

### Responses API (`cmd_test`)

Three requirements differ from the standard Chat Completions API:

- Content type must be `"input_text"` — `"text"` is rejected
- `store=False` is mandatory — omitting it causes an error
- `instructions` (system prompt) is required

WHAM is **stateless**: the full conversation history must be sent in the `input` array on
every request.

For multi-turn sessions, pass the same UUID v7 as both `prompt_cache_key` and the
`session_id` request header to enable server-side prompt caching and reduce TTFT.

### Models Endpoint (`cmd_list`)

WHAM's `/models` schema differs from the standard API:

| Field | Standard API | WHAM |
|---|---|---|
| Response key | `data` | `models` |
| Model identifier | `id` | `slug` |
| Required query | — | `client_version` |

Use `with_raw_response` because the openai library cannot parse the non-standard schema.

The `/models` response also includes server-managed system prompts per model:
`base_instructions` (agent behavior directives) and `model_messages` (user-facing templates
and persona definitions).

### Refer to `codex_oauth.py`

See inline comments and docstrings in `codex_oauth.py` for full implementation details.
