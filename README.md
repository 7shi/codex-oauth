# Codex OAuth

Sample implementation of **Sign in with ChatGPT — ChatGPT plan usage for open-source apps**
in Python, using the `openai-python` library.

Eligible ChatGPT Plus and Pro users sign in with their ChatGPT account and run Responses API
requests against their ChatGPT plan, without an API key. The sample implementation is in
[codex_oauth.py](codex_oauth.py); the exact rules it follows are collected in [SPEC.md](SPEC.md).

- This is a minimal sample, not a production-ready auth framework.
- It manages one ChatGPT account per credential file (no account picker).
- Device-code (headless) sign-in is out of scope; no official equivalent exists for this flow.

For practical use, see [llm7shi](https://github.com/7shi/llm7shi), which builds on the findings of
this repository. Its `chatgpt:` provider runs models on the ChatGPT plan. Unlike this sample, its
sign-in opens the browser and receives the callback on a loopback listener; pasting the redirected
URL remains available with `--url` for SSH sessions and VMs. It also stores the tokens encrypted
under a key in the OS keyring.

> **About the name**: `codex-oauth` is historical. Versions up to 0.0.1 reused the Codex CLI
> client ID and an undocumented backend. Since 0.1.0 the code uses only the officially documented
> flow and no Codex credentials.

## Disclaimer

This repository is provided **AS IS**, with **NO WARRANTY** of any kind (express or
implied), including but not limited to merchantability, fitness for a particular purpose,
and non-infringement. You assume all risks and are solely responsible for any use,
misuse, or consequences arising from it.

The implementation is based on the official documentation as of 2026-11-26. ChatGPT plan usage
is a **preview** feature and may change.

## Official documentation

| Topic | Page |
|---|---|
| Overview, host ID | https://developers.openai.com/siwc/token-sharing-open-source |
| Registration and sign-in | https://developers.openai.com/siwc/token-sharing-open-source/sign-in |
| Accounts, refresh, sign-out | https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions |
| Token reference | https://developers.openai.com/siwc/token-sharing-open-source/token-reference |
| Errors and recovery | https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery |
| Models and inference | https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference |
| Preview limitations | https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations |
| UI/UX guidelines | https://developers.openai.com/siwc/ui-ux-guidelines |

## Requirements

- Python 3.13+
- ChatGPT account
- A browser (on any machine; you paste the redirected URL back into the terminal)

ChatGPT plan usage is available to all open-source apps through dynamic client registration;
no client secret, partner API key, or separate application form is needed.

For ChatGPT Plus users, the five-hour usage limit is shared across all apps that use the ChatGPT
plan; it does not apply to Pro users. Review and manage app usage at
[ChatGPT Settings → Usage](https://chatgpt.com/settings/usage).

Dependencies (`pyproject.toml`):

```toml
dependencies = [
    "httpx>=0.28.1",
    "openai>=2.21.0",
    "pyjwt[crypto]>=2.10",
]
```

`httpx` is used for the OAuth endpoints; `pyjwt[crypto]` verifies the ID token signature.

## Setup & Usage

Install or clone the repository:

```bash
# To clone and develop this project.
git clone https://github.com/7shi/codex-oauth.git
cd codex-oauth
uv sync

# In another project, add directly from Git.
uv add https://github.com/7shi/codex-oauth.git
```

Run the available commands:

```bash
uv run codex_oauth login            # Sign in with ChatGPT, saves auth.json
uv run codex_oauth login --consent  # ask again for plan usage after declining it
uv run codex_oauth list             # list available models
uv run codex_oauth test             # stream a test request with the last listed model
uv run codex_oauth test -m <slug>   # specify model
uv run codex_oauth test --effort medium  # also show the reasoning summary
uv run codex_oauth logout           # revoke the session and clear tokens
```

> **Note**: The direct file form (`uv run codex_oauth.py`) and the module form
> (`uv run python -m codex_oauth`) are equivalent alternatives.

`list` and `test` refresh the access token automatically when it is near expiry, and retry once
after an HTTP 401.

### Library usage

```python
from codex_oauth import AuthManager

auth = AuthManager()
auth.ensure_valid()
client = auth.make_client()

with client.responses.create(
    model="<slug from list>",
    input=[{"role": "user", "content": "Hello"}],
    store=False,   # required
    stream=True,   # required
) as stream:
    ...
```

### Tests

Offline tests mock the OpenAI endpoints, so they need no account or network:

```bash
uv run pytest
```

- `tests/test_auth_flow.py`: sign-in, reauthorization, refresh, sign-out, ID token checks
- `tests/test_inference.py`: `list` / `test`, streaming events, error handling

## How it works

### Files

| File | Content |
|---|---|
| `host.json` | This host's `ext_agent_host_id` (`urn:uuid:<uuid4>`), created once before the first sign-in |
| `auth.json` | Credential record: issued `client_id`, verified identity (`subject`, `email`), tokens, granted `scopes`, `expires_in`, `saved_at` |

The host ID is kept separate from the credentials so that copying `auth.json` to another machine
(for example a self-hosted VM) never overwrites that machine's host ID.
Both files are written atomically with mode `0600`.

### `login`

1. Load or create the host ID.
2. Print an authorization URL for `https://auth.openai.com/api/accounts/authorize` with
   `redirect_uri=http://127.0.0.1:1455/auth/callback`, `response_type=code`, `scope`
   (`openid profile email offline_access resource.invoke chatgpt.tokens.use.direct`),
   `resource=https://api.openai.com/v1`, fresh `state` / `nonce` / PKCE (S256), and
   `ext_agent_host_id`.
   - **First registration:** `client_id=dynamic_agent_client` and `agent_name_hint=codex-oauth`.
   - **Reauthorization:** the saved issued `client_id` and `login_hint` (verified email).
     `id_token_hint` is not sent, because the URL is shown on screen and must not carry the ID token.
3. Open the URL in a browser and sign in. No listener runs, so the browser ends on a page that fails
   to load at `http://127.0.0.1:1455/auth/callback?code=...`. Copy that URL from the address bar
   and paste it at the `Callback URL:` prompt (the query string alone is also accepted).
4. From the pasted URL, validate `state` first, then stop on `error`. A new registration must return
   an issued `client_id` (`oaiapp_...`); a reauthorization returning a different one is rejected.
5. Exchange the code at `https://auth.openai.com/api/accounts/oauth/token` (no client secret).
6. Verify the ID token: RS256 signature against `jwks_uri` from the
   [discovery document](https://auth.openai.com/.well-known/openid-configuration), issuer,
   audience = issued client ID, expiration, and nonce. On reauthorization, `sub` must match the saved
   account.
7. Save the record. If `chatgpt.tokens.use.direct` was not granted, the sign-in is kept but
   `list` / `test` refuse to run until `login --consent` grants it.

### Refresh

When fewer than 5 minutes remain on the 1-hour access token, `refresh()` posts
`grant_type=refresh_token` with the issued `client_id`, the refresh token, and `resource` (no `scope`).
The refresh token (valid 30 days) rotates on every refresh, so the call is serialized with a file
lock (`auth.json.lock`) and the replacement is saved immediately.

`invalid_grant`, `invalid_refresh_token`, `token_expired`, `refresh_token_expired`,
`refresh_token_invalidated` and `refresh_token_reused` end the session: tokens are cleared (the
client ID is kept) and you must run `login` again. Other failures keep the credentials.

### `logout`

Posts `token=<refresh_token>`, `token_type_hint=refresh_token` and `client_id` to the
`revocation_endpoint` from discovery, retrying network/5xx failures. Tokens are cleared even if
revocation could not be confirmed (you are told so; disconnect the app in ChatGPT Settings in that
case). The client ID and host ID are kept so that the next `login` reuses the registration.

### Inference rules

- Endpoint: `POST https://api.openai.com/v1/responses` with `Authorization: Bearer <access_token>`.
  Do not use ChatGPT `backend-api` endpoints.
- `store: false` and `stream: true` on every request; send the full history in `input`.
- System prompt: use `instructions` or developer messages; `role: "system"` message items are rejected.
- Unsupported fields include `max_output_tokens`, `temperature`, `top_p`, `metadata`, `truncation`,
  `user`, `previous_response_id` and others (see the
  [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)).
- A request succeeds only after `response.completed`; `response.failed`, `response.incomplete` and
  interrupted streams are reported as failures.
- Models: `GET https://api.openai.com/v1/models` returns `models[]`; entries with
  `visibility == "list"` are shown in server order, and `slug` is passed as `model`.

### Errors

After a successful `test`, the token usage of that request (`usage` from `response.completed`)
is printed. Remaining five-hour or weekly limits are not available through the API; check them at
[ChatGPT Settings → Usage](https://chatgpt.com/settings/usage).

Documented `subscription_sharing_*` / `chatpass_v2_*` codes are printed with their recovery hint,
the HTTP status and the request ID. There is no automatic retry loop. On
`subscription_sharing_usage_limit_exceeded`, review the limit at
[ChatGPT Settings → Usage](https://chatgpt.com/settings/usage).

## Security notes

- `auth.json` contains bearer credentials (access, refresh and ID tokens). Do not share, commit,
  or upload it. `.gitignore` already excludes it, but backups and logs are your responsibility.
- **Not implemented in this sample:** `auth.json` is stored as **plain-text JSON**, protected only
  by owner-only file permissions (`0600`). This meets the documented minimum, but any process running
  as the same user can read it, and on Windows `0600` has little effect. A real app should store
  the tokens in the OS credential store (e.g. via the `keyring` library: macOS Keychain, Windows
  Credential Manager, Linux Secret Service) and fall back to a `0600` file only where no store is
  available, such as headless Linux or SSH sessions.
- The CLI never prints tokens.
- If credentials are compromised, disconnect the app in ChatGPT Settings.

## Troubleshooting

- **Old `auth.json`:** files from 0.0.1 are not compatible. `list` / `test` ask you to run `login`;
  `login` moves the old file to `auth.json.old` and registers a new client.
- **"This site can't be reached" after sign-in:** expected. Copy the URL from the address bar and
  paste it into the terminal. Because nothing listens on `127.0.0.1`, the browser may run on a
  different machine than `login` (e.g. `login` over SSH on a VM).
- **`state mismatch`:** the pasted URL is from another attempt. Paste the URL from the attempt that
  `login` just printed, or run `login` again.
- **`The pasted URL does not start with ...`:** paste the redirected URL, not the authorization URL.
- **Plan usage not granted:** run `login --consent`.
- **Another account:** this sample keeps one account per `auth.json`; to register a different
  account, move `auth.json` away and run `login`.
