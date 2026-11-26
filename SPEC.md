# SPEC: Sign in with ChatGPT — plan usage for open-source apps

Verbatim facts extracted from the official documentation, retrieved **2026-11-26**.
Every constant and behavior in `codex_oauth.py` is traceable to a row below.

- Docs bundle: https://developers.openai.com/siwc/llms-full.txt
- Discovery: https://auth.openai.com/.well-known/openid-configuration

Page abbreviations: **OV** = [overview](https://developers.openai.com/siwc/token-sharing-open-source),
**SI** = [sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in),
**PS** = [profiles-and-sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions),
**TR** = [token-reference](https://developers.openai.com/siwc/token-sharing-open-source/token-reference),
**ER** = [errors-and-recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery),
**MI** = [models-and-inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference),
**PL** = [preview-limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations),
**WS** = [website](https://developers.openai.com/siwc/website),
**QS** = [quickstart](https://developers.openai.com/siwc/quickstart),
**UX** = [ui-ux-guidelines](https://developers.openai.com/siwc/ui-ux-guidelines).

## Discovery document (fetched 2026-11-26)

| Key | Value |
|---|---|
| `issuer` | `https://auth.openai.com` |
| `authorization_endpoint` | `https://auth.openai.com/api/accounts/authorize` |
| `token_endpoint` | `https://auth.openai.com/api/accounts/oauth/token` |
| `revocation_endpoint` | `https://auth.openai.com/api/accounts/oauth/revoke` |
| `jwks_uri` | `https://auth.openai.com/.well-known/jwks.json` |
| `id_token_signing_alg_values_supported` | `["RS256"]` |
| `code_challenge_methods_supported` | `["S256"]` |
| `token_endpoint_auth_methods_supported` | includes `none` |

The code reads `jwks_uri`, `revocation_endpoint`, `issuer` and the allowed algorithms from
discovery at runtime (PS: "using the `revocation_endpoint` from …openid-configuration";
WS: "`createRemoteJWKSet` … with the discovery document's `jwks_uri`").

## Host identity (OV)

- `ext_agent_host_id` is **required**, chosen and persisted **before the first sign-in**, distinct per host,
  opaque (not an email/user ID), not a credential.
- Accepted formats: `urn:ietf:params:oauth:jwk-thumbprint:…` (recommended, optional),
  `urn:uuid:<UUIDv4>` (supported), `did:key:<key>`.
- Self-hosted VMs: "Preserve the host ID assigned to the VM when importing the credentials so a copied
  laptop ID does not overwrite it."

## Authorization request (SI §2)

`GET https://auth.openai.com/api/accounts/authorize`, each value URL-encoded.

| Parameter | Rule |
|---|---|
| `client_id` | `dynamic_agent_client` on first registration; the issued ID afterwards |
| `agent_name_hint` | App's actual name, consistent across installations; **first registration only**; omit on reauthorization |
| `ext_agent_host_id` | Required |
| `id_token_hint` | Reauthorization only: retained ID token (may be expired). Omit after sign-out or if none |
| `login_hint` | Reauthorization only, optional: saved email from the validated ID token |
| `response_type` | `code` |
| `redirect_uri` | `http://127.0.0.1:<port>/auth/callback`; never `localhost`; listener started before the browser; later sign-ins may change **only the port**; same exact URI in authorize and exchange |
| `scope` | `openid profile email` + `offline_access resource.invoke chatgpt.tokens.use.direct` |
| `resource` | `https://api.openai.com/v1` |
| `state` | Fresh random per attempt |
| `nonce` | Fresh random per attempt |
| `code_challenge_method` | `S256` |
| `code_challenge` | base64url(SHA-256(verifier)), no padding |

Re-enabling plan usage after decline (ER): repeat OAuth with the saved client ID and the complete scope
set; use `prompt=consent` (`force_reconsent=true` only after OpenAI confirms deployment). Do not force
consent on every sign-in.

## Callback (SI §3)

- Validate `state` first; on `error` (e.g. `access_denied`) stop and do not exchange.
- New registration returns `code`, `state`, issued `client_id` (e.g. `oaiapp_...`), maybe `scope`.
  Missing issued `client_id` → registration incomplete. Never save `dynamic_agent_client`.
- Reauthorization may omit `client_id`; if it supplies a **different** one, reject.

## Code exchange (SI §3)

Form POST to `token_endpoint`: `grant_type=authorization_code`, issued `client_id`, `code`,
`code_verifier`, same `redirect_uri`, same `resource`. No client secret.
`invalid_grant` → discard the code and start a fresh authorization.

Token response (TR): `access_token`, `refresh_token`, `id_token`, `token_type`, `expires_in`, `scope`,
`earliest_refresh_at`. HTTP 200.

## ID token validation (SI §4, WS §6)

- Signature against JWKS; issuer; audience = issued client ID; expiration; nonce of this attempt.
- WS example: `requiredClaims: ["sub","exp","iat"]`, `clockTolerance: 5`; `sid` if present must be a
  non-empty string. Sample `aud` is an array.
- Identity = `sub`. Returning account: new `sub` must match the selected account before replacing credentials.
- Email is verified only when `email` is non-empty and `email_verified is True`.

## Plan permission (SI §4, ER)

Require `chatgpt.tokens.use.direct` in the token response's granted scopes. If missing with a valid ID
token: **retain the sign-in, mark plan usage disabled**, do not run inference.

## Credential record (SI §5)

Fields: `email`, `issuer`, `subject`, `client_id`, `ext_agent_host_id`, `id_token`, `access_token`,
`refresh_token`, `token_type`, `expires_in`, `scopes` (split of `scope`), `saved_at` (UTC timestamp
of token response). Atomic write, `0600`. After refresh replace access token, expiry, scopes and
refresh token together.

## Refresh (PS, TR, ER)

- Form POST: `grant_type=refresh_token`, issued `client_id` (not `dynamic_agent_client`),
  `refresh_token`, `resource=https://api.openai.com/v1`; **omit `scope`**.
- Access token 1 h; refresh token 30 days, rotated on every refresh. Serialize refreshes across processes.
- Terminal codes: `invalid_grant`, `invalid_refresh_token`, `token_expired`, `refresh_token_expired`,
  `refresh_token_invalidated`, `refresh_token_reused` → clear tokens, repeat OAuth with saved client ID.
- `invalid_client` → fix client configuration.

## Sign-out (PS)

Form POST to `revocation_endpoint`: `token=<refresh_token>`, `token_type_hint=refresh_token`,
`client_id`. Empty HTTP 200 = success (also for already-invalid token). Network/5xx → retry with
backoff; if unconfirmed, clear tokens anyway and tell the user (they can disconnect in ChatGPT Settings).
Keep client ID / account mapping and host ID.

## Inference (MI, PL)

- `GET https://api.openai.com/v1/models` (bearer) → `models[]`; keep `visibility == "list"` in server
  order; show `display_name`, pass `slug` as `model`.
- `POST https://api.openai.com/v1/responses` only; `store: false`, `stream: true` on every request;
  `input` as an array. SDK example uses `max_retries=0`.
- System prompt: "Use `instructions` or developer messages; explicit `{type: "message", role: "system"}`
  items are rejected."
- Unsupported fields: `background`, `conversation`, `max_output_tokens`, `max_tool_calls`, `metadata`,
  `moderation`, `multi_agent`, `prompt`, `prompt_cache_retention`, `safety_identifier`, `temperature`,
  `top_logprobs`, `top_p`, `truncation`, `user`; also `previous_response_id` over HTTP.
- Success only after `response.completed`; handle `response.failed`, `response.incomplete`, errors and
  interrupted streams separately.

## Errors (ER)

Before stream: body may be `{"detail": "..."}`; 401 (identity/permission not accepted), 403 (policy/region),
503 (direct routing unavailable — bounded backoff). Structured codes:

| Code | HTTP | Action |
|---|---|---|
| `subscription_sharing_user_not_eligible` | 403 | Explain; do not retry or loop OAuth |
| `subscription_sharing_usage_limit_exceeded` | 429 | Pause; link https://chatgpt.com/settings/usage |
| `subscription_sharing_usage_unavailable` | 503 | Keep credentials; retry later |
| `subscription_sharing_unsupported_capability` | 400 | Inspect `error.param`; remove it |
| `subscription_sharing_route_not_supported` | 403 | Check method/endpoint |
| `subscription_sharing_invalid_user` | 401 | Diagnose; sign in again after terminal refresh error |
| `chatpass_v2_scope_not_authorized`, `chatpass_v2_invalid_authorization_context` | 403 | Check client/grant config |
| `subscription_sharing_user_unavailable` | 503 | Keep credentials; retry later |

## Credential hygiene (PS)

Tokens never in logs or URLs. `id_token_hint` only to the authorize endpoint; redact authorization URLs
that contain it.

## Eligibility and UX (QS, PS, UX)

- "ChatGPT plan usage is available to all open-source partners and selected private clients." The
  "Request a client ID" waitlist applies to commercial Sign in with ChatGPT; the OSS flow "needs neither a
  client secret nor a partner API key" (SI).
- Plus and Pro users. Plus: five-hour limit shared across all apps; not applicable to Pro.
- Labels: **Continue with ChatGPT** / **Sign in with ChatGPT**. Usage link: https://chatgpt.com/settings/usage.

## Assumptions (not stated explicitly by the docs)

1. **Eligibility:** a self-published OSS sample needs no form or registration beyond dynamic
   registration (based on QS + SI quotes above).
2. **Port:** the redirect URI is always `http://127.0.0.1:1455/auth/callback` (the docs example).
3. **Pasted callback (deviation):** SI says to start a loopback listener before opening the browser.
   This sample deliberately runs no listener and does not open the browser: it prints the
   authorization URL, and the user pastes the redirected URL (which fails to load) back into the
   terminal. `state`, `error`, `code` and `client_id` are read from the pasted URL with the same rules
   as a callback. The redirect URI value itself still follows the SI rules.
4. **`id_token_hint` omitted:** because the authorization URL is displayed for copying, and URLs that
   contain `id_token_hint` must be kept out of logs (PS), reauthorization sends only `login_hint`.
   SI makes the hint optional ("A retained `id_token_hint` identifies the original account"); without
   it the account selector is shown.
5. **`earliest_refresh_at`:** meaning not documented. It is stored but not used; refresh is driven by
   `expires_in` with a 5-minute margin. Observed on 2026-11-26: it is a Unix time about 54 minutes
   (90% of `expires_in`) after issuance, and a refresh well before it was accepted, so it appears to
   be a recommended time rather than an enforced one.
6. **Host ID storage:** the SI record example includes `ext_agent_host_id`, but the VM guide says the host
   ID must survive credential import. The host ID is therefore kept in its own file (`host.json`) and
   copied into the credential record for reference; `host.json` is authoritative.
7. **Refresh-issued ID token:** if a refresh response contains an `id_token`, it is verified like the
   original (without nonce, which is bound to the authorization request) and must have the same `sub`.
8. **Error body shape for refresh:** the code reads `error` as either a string (RFC 6749) or an object
   with `code`.
9. **ID token on 401 retry:** after an inference 401, one refresh-and-retry is attempted (standard
   pattern); the docs do not forbid it.
