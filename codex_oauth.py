"""Sample implementation of "Sign in with ChatGPT" plan usage for open-source apps.

Every constant and behavior below follows OpenAI's official documentation:
https://developers.openai.com/siwc/token-sharing-open-source
See SPEC.md for the exact rules (with links) that this module implements.
"""

import argparse
import base64
import contextlib
import datetime
import functools
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
import uuid
from urllib.parse import parse_qs, quote, urlencode

import httpx
import jwt
from openai import APIStatusError, AuthenticationError, OpenAI

# --- Constants (sources: SPEC.md) -------------------------------------------

DISCOVERY_URL = "https://auth.openai.com/.well-known/openid-configuration"
AUTHORIZE_URL = "https://auth.openai.com/api/accounts/authorize"  # sign-in §2
TOKEN_URL     = "https://auth.openai.com/api/accounts/oauth/token"  # sign-in §3, refresh
API_BASE      = "https://api.openai.com/v1"                         # models-and-inference
RESOURCE      = "https://api.openai.com/v1"                         # authorize, exchange, refresh

REGISTRATION_CLIENT_ID = "dynamic_agent_client"  # first-time registration entrypoint only
AGENT_NAME_HINT = "codex-oauth"                  # this app's actual name (first registration only)
PLAN_SCOPE = "chatgpt.tokens.use.direct"
SCOPES = ["openid", "profile", "email", "offline_access", "resource.invoke", PLAN_SCOPE]

CALLBACK_HOST = "127.0.0.1"  # never "localhost"
CALLBACK_PATH = "/auth/callback"
CALLBACK_PORT = 1455         # docs example; the redirect is pasted back, so no listener binds it

REFRESH_MARGIN = 300  # refresh when less than 5 minutes of the 1-hour access token remain
CLOCK_LEEWAY   = 5    # seconds of clock skew allowed for ID-token validation

USAGE_URL = "https://chatgpt.com/settings/usage"

AUTH_PATH   = "auth.json"
HOST_PATH   = "host.json"

# Refresh error codes that make the refresh token unusable (errors-and-recovery).
TERMINAL_REFRESH_ERRORS = {
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
}

# Structured Responses error codes and their documented recovery (errors-and-recovery).
ERROR_HINTS = {
    "subscription_sharing_user_not_eligible":
        "ChatGPT plan usage is unavailable for this user, workspace, or policy.",
    "subscription_sharing_usage_limit_exceeded":
        f"Usage limit reached (plan or app-specific). Review it at {USAGE_URL}",
    "subscription_sharing_usage_unavailable":
        "Usage availability could not be checked. Try again later.",
    "subscription_sharing_unsupported_capability":
        "The request used an unsupported input, tool, feature, model, or service tier (see param).",
    "subscription_sharing_route_not_supported":
        "This HTTP method/endpoint is not supported for ChatGPT plan usage.",
    "subscription_sharing_invalid_user":
        "The subscriber context could not be validated. Run `login` again if this persists.",
    "chatpass_v2_scope_not_authorized":
        "The granted permission does not authorize this operation. Check the client and grant.",
    "chatpass_v2_invalid_authorization_context":
        "The granted permission does not authorize this operation. Check the client and grant.",
    "subscription_sharing_user_unavailable":
        "User/workspace information is temporarily unavailable. Try again later.",
}

__all__ = [
    "AuthManager",
    "LoginRequired",
    "PlanUsageDisabled",
    "OAuthError",
    "InferenceError",
    "cmd_login",
    "cmd_logout",
    "list_models",
    "verify_id_token",
]


# --- Errors -----------------------------------------------------------------

class LoginRequired(Exception):
    """No usable credentials; the user must run `login`."""


class PlanUsageDisabled(Exception):
    """Signed in, but `chatgpt.tokens.use.direct` was not granted."""


class OAuthError(Exception):
    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


class InferenceError(Exception):
    def __init__(self, code: str, message: str = "", param: str | None = None):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.param = param


# --- Small helpers ----------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def _write_json_atomic(path: str, data: dict):
    """Write via temp file + rename with owner-only permissions (sign-in §5)."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def _file_lock(path: str):
    """Serialize token rotation across processes (profiles-and-sessions: Refreshing tokens).

    Uses fcntl where available (Unix). On other platforms the lock is a no-op.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return
    with open(path + ".lock", "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _is_old_format(data: dict) -> bool:
    """auth.json written by the old Codex-client-ID implementation (<= 0.0.1)."""
    return "client_id" not in data and ("access" in data or data.get("type") == "oauth")


def load_host_id(path: str = HOST_PATH) -> str:
    """Load or create this host's `ext_agent_host_id` (overview: Host-ID).

    Kept in its own file so that importing a credential file from another
    machine never overwrites this host's ID (self-hosted VMs guide).
    """
    data = _read_json(path)
    if data and data.get("ext_agent_host_id"):
        return data["ext_agent_host_id"]
    host_id = f"urn:uuid:{uuid.uuid4()}"
    _write_json_atomic(path, {"ext_agent_host_id": host_id})
    return host_id


@functools.cache
def fetch_discovery() -> dict:
    resp = httpx.get(DISCOVERY_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


@functools.cache
def _jwks_client(jwks_uri: str) -> jwt.PyJWKClient:
    # PyJWKClient caches keys and refetches when an unknown `kid` appears.
    return jwt.PyJWKClient(jwks_uri)


def verify_id_token(id_token: str, client_id: str, nonce: str | None) -> dict:
    """Validate an ID token (sign-in §4, website §6).

    Checks signature (JWKS from discovery), issuer, audience (= issued client ID),
    expiration, required claims, and the nonce of this authorization attempt.
    `nonce=None` is used only for an ID token returned by a refresh.
    """
    disc = fetch_discovery()
    algorithms = [a for a in disc.get("id_token_signing_alg_values_supported", []) if a != "none"]
    key = _jwks_client(disc["jwks_uri"]).get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        key.key,
        algorithms=algorithms,
        audience=client_id,
        issuer=disc["issuer"],
        leeway=CLOCK_LEEWAY,
        options={"require": ["sub", "exp", "iat"]},
    )
    if nonce is not None and claims.get("nonce") != nonce:
        raise OAuthError("The ID token nonce did not match.")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OAuthError("The ID token did not contain a subject.")
    sid = claims.get("sid")
    if sid is not None and (not isinstance(sid, str) or not sid.strip()):
        raise OAuthError("The ID token contained an invalid session identifier.")
    return claims


def _post_token(data: dict) -> dict:
    """Form POST to the token endpoint; raises OAuthError with the error code."""
    resp = httpx.post(TOKEN_URL, data=data, headers={"Accept": "application/json"}, timeout=30)
    if resp.status_code == 200:
        return resp.json()
    try:
        body = resp.json()
    except ValueError:
        body = {}
    err = body.get("error")
    if isinstance(err, dict):  # tolerate a nested error object
        code, desc = err.get("code"), err.get("message")
    else:
        code, desc = err, body.get("error_description")
    request_id = resp.headers.get("openai-request-id") or resp.headers.get("x-request-id")
    msg = f"Token endpoint returned HTTP {resp.status_code}"
    if code:
        msg += f" ({code})"
    if desc:
        msg += f": {desc}"
    if request_id:
        msg += f" [request_id={request_id}]"
    raise OAuthError(msg, code)


# --- AuthManager ------------------------------------------------------------

class AuthManager:
    """Holds one credential record (sign-in §5) and keeps its access token fresh."""

    TOKEN_FIELDS = ("id_token", "access_token", "refresh_token", "token_type",
                    "expires_in", "earliest_refresh_at", "scopes", "saved_at")

    def __init__(self, path: str = AUTH_PATH):
        self.path = path
        self.data = self._load()

    def _load(self) -> dict:
        data = _read_json(self.path) or {}
        if _is_old_format(data):
            raise LoginRequired(
                f"{self.path} was written by the old Codex-based version and is not "
                "compatible. Run `login` to sign in with ChatGPT again."
            )
        return data

    def save(self):
        _write_json_atomic(self.path, self.data)

    @property
    def plan_enabled(self) -> bool:
        return PLAN_SCOPE in self.data.get("scopes", [])

    @property
    def expires_at(self) -> float:
        saved_at = self.data.get("saved_at")
        if not saved_at:
            return 0
        start = datetime.datetime.fromisoformat(saved_at).timestamp()
        return start + int(self.data.get("expires_in") or 0)

    def clear_tokens(self):
        """Drop tokens but keep the client/account mapping (profiles-and-sessions)."""
        for k in self.TOKEN_FIELDS:
            self.data.pop(k, None)

    def ensure_valid(self):
        if not self.data.get("refresh_token"):
            raise LoginRequired("Not signed in. Run `login`.")
        if not self.plan_enabled:
            raise PlanUsageDisabled(
                f"ChatGPT plan usage ({PLAN_SCOPE}) was not granted. "
                "Run `login --consent` to enable it."
            )
        if self.expires_at - REFRESH_MARGIN < time.time():
            self.refresh()

    def refresh(self):
        """Rotate the refresh token (profiles-and-sessions: Refreshing tokens)."""
        with _file_lock(self.path):
            # Re-read under the lock: another process may have rotated the token
            # (use its result) or signed out (stop) while we waited.
            previous = self.data.get("refresh_token")
            self.data = self._load()
            if not self.data.get("refresh_token"):
                raise LoginRequired("Not signed in. Run `login`.")
            if (self.data["refresh_token"] != previous
                    and self.expires_at - REFRESH_MARGIN >= time.time()):
                return
            try:
                tokens = _post_token({
                    "grant_type":    "refresh_token",
                    "client_id":     self.data["client_id"],  # issued ID, never dynamic_agent_client
                    "refresh_token": self.data["refresh_token"],
                    "resource":      RESOURCE,
                    # `scope` omitted to retain the grant
                })
            except OAuthError as e:
                if e.code in TERMINAL_REFRESH_ERRORS:
                    self.clear_tokens()
                    self.save()
                    raise LoginRequired(f"{e}\nThe session has ended. Run `login` again.") from e
                if e.code == "invalid_client":
                    raise OAuthError(f"{e}\nThe saved client ID was rejected.", e.code) from e
                raise  # temporary failure: keep credentials
            if id_token := tokens.get("id_token"):
                claims = verify_id_token(id_token, self.data["client_id"], nonce=None)
                if claims["sub"] != self.data.get("subject"):
                    raise OAuthError("Refreshed ID token belongs to a different account.")
            self._apply_tokens(tokens)
            self.save()

    def _apply_tokens(self, tokens: dict):
        """Replace access token, expiry, scopes and refresh token together (sign-in §5)."""
        self.data["access_token"]  = tokens["access_token"]
        self.data["refresh_token"] = tokens["refresh_token"]
        self.data["token_type"]    = tokens.get("token_type", "Bearer")
        self.data["expires_in"]    = int(tokens.get("expires_in") or 3600)
        self.data["saved_at"]      = _utc_now_iso()
        if "id_token" in tokens:
            self.data["id_token"] = tokens["id_token"]
        if "scope" in tokens:
            self.data["scopes"] = tokens["scope"].split()
        if "earliest_refresh_at" in tokens:
            self.data["earliest_refresh_at"] = tokens["earliest_refresh_at"]

    def make_client(self) -> OpenAI:
        """The access token is the bearer credential; no extra headers are documented."""
        return OpenAI(api_key=self.data["access_token"], base_url=API_BASE, max_retries=0)

    def auto_refresh(self, f, *args, **kwargs):
        """Refresh if near expiry, call f(self, ...), and retry once after a 401."""
        self.ensure_valid()
        try:
            return f(self, *args, **kwargs)
        except AuthenticationError:
            self.refresh()
            return f(self, *args, **kwargs)


# --- login ------------------------------------------------------------------

def _read_pasted_callback(redirect_uri: str) -> dict:
    """Ask the user to paste the URL the browser was redirected to.

    Nothing listens on the loopback address, so the browser shows a connection
    error after sign-in; its address bar still holds `code`, `state` and (on a
    new registration) the issued `client_id`. A bare query string is accepted too.
    """
    print("After signing in, the browser is redirected to a page that fails to load:")
    print(f"  {redirect_uri}?code=...")
    print("Copy the full URL from the address bar and paste it here.")
    try:
        pasted = input("Callback URL: ").strip()
    except EOFError:
        pasted = ""
    if not pasted:
        raise OAuthError("No URL was pasted.")
    if "?" in pasted:
        base, query = pasted.split("?", 1)
        if base and base != redirect_uri:
            raise OAuthError(f"The pasted URL does not start with {redirect_uri}.")
    else:
        query = pasted
    return {k: v[0] for k, v in parse_qs(query.split("#", 1)[0]).items()}


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def cmd_login(auth_path: str = AUTH_PATH, host_path: str = HOST_PATH, consent: bool = False):
    """Sign in with ChatGPT (sign-in §1-§5).

    First run: registers a client with `dynamic_agent_client` and saves the issued
    client ID. Later runs: reauthorize with the saved client ID and the same host ID.
    """
    host_id = load_host_id(host_path)

    record = _read_json(auth_path) or {}
    old_format = _is_old_format(record)
    if old_format:
        print(f"{auth_path} is from the old Codex-based version; starting a new registration.")
        record = {}
    client_id = record.get("client_id")
    registering = client_id is None

    # No listener is started: the user pastes the redirected URL instead.
    redirect_uri = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{CALLBACK_PATH}"
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()

    params = {
        "response_type":         "code",
        "client_id":             REGISTRATION_CLIENT_ID if registering else client_id,
        "ext_agent_host_id":     host_id,
        "redirect_uri":          redirect_uri,
        "scope":                 " ".join(SCOPES),
        "resource":              RESOURCE,
        "state":                 state,
        "nonce":                 nonce,
        "code_challenge_method": "S256",
        "code_challenge":        challenge,
    }
    if registering:
        params["agent_name_hint"] = AGENT_NAME_HINT
    elif record.get("email"):
        params["login_hint"] = record["email"]
    # `id_token_hint` is not sent: the URL is printed for the user to copy, and
    # URLs containing it must be kept out of logs (profiles-and-sessions).
    if consent:
        params["prompt"] = "consent"  # re-request plan usage after an earlier decline
    auth_url = f"{AUTHORIZE_URL}?{urlencode(params, quote_via=quote)}"

    print("Registering a new client" if registering else f"Reauthorizing client {client_id}")
    print(f"Open this URL in your browser to Sign in with ChatGPT:\n\n{auth_url}\n")
    result = _read_pasted_callback(redirect_uri)
    # Validate state before looking at anything else (sign-in §3).
    if result.get("state") != state:
        raise OAuthError("state mismatch (possible CSRF or a URL from another attempt).")
    if "error" in result:
        if result["error"] == "access_denied":
            raise OAuthError("Consent was declined; nothing was saved.", "access_denied")
        raise OAuthError(f"Authorization failed: {result.get('error_description') or result['error']}",
                         result["error"])
    if not result.get("code"):
        raise OAuthError("The callback did not contain an authorization code.")

    returned_client_id = result.get("client_id")
    if registering:
        if not returned_client_id or returned_client_id == REGISTRATION_CLIENT_ID:
            raise OAuthError("Registration incomplete: the callback did not include an issued client_id.")
        client_id = returned_client_id
    elif returned_client_id and returned_client_id != client_id:
        raise OAuthError(f"The callback returned a different client_id ({returned_client_id}); "
                         "rejected, the existing registration is kept.")

    try:
        tokens = _post_token({
            "grant_type":    "authorization_code",
            "client_id":     client_id,
            "code":          result["code"],
            "code_verifier": verifier,
            "redirect_uri":  redirect_uri,
            "resource":      RESOURCE,
        })
    except OAuthError as e:
        if e.code == "invalid_grant":
            raise OAuthError(f"{e}\nThe code was discarded. Run `login` again.", e.code) from e
        raise
    for k in ("id_token", "access_token", "refresh_token"):
        if not tokens.get(k):
            raise OAuthError(f"The token response did not contain {k}.")

    claims = verify_id_token(tokens["id_token"], client_id, nonce)
    if record.get("subject") and claims["sub"] != record["subject"]:
        raise OAuthError("Signed in as a different account than the saved registration; "
                         "credentials were not replaced.")

    if old_format and os.path.exists(auth_path):
        os.replace(auth_path, auth_path + ".old")
        print(f"Old credentials moved to {auth_path}.old")

    auth = AuthManager.__new__(AuthManager)
    auth.path = auth_path
    email = claims.get("email") if claims.get("email_verified") is True else None
    auth.data = {
        "email":             email or record.get("email"),
        "issuer":            claims["iss"],
        "subject":           claims["sub"],
        "client_id":         client_id,
        "ext_agent_host_id": host_id,
    }
    auth._apply_tokens(tokens)
    auth.save()

    expires = datetime.datetime.fromtimestamp(auth.expires_at).strftime("%Y-%m-%d %H:%M:%S")
    print("\n=== Signed in with ChatGPT ===")
    print(f"Account    : {auth.data['email'] or claims['sub']}")
    print(f"Client ID  : {client_id}")
    print(f"Host ID    : {host_id}")
    print(f"Scopes     : {' '.join(auth.data['scopes'])}")
    print(f"Expires    : {expires}")
    print(f"Saved to {auth_path}")
    if auth.plan_enabled:
        print(f"\nYou're using your ChatGPT plan. Manage usage: {USAGE_URL}")
    else:
        print(f"\nChatGPT plan usage ({PLAN_SCOPE}) was not granted; inference is disabled.\n"
              "Run `login --consent` to enable it.")


# --- logout -----------------------------------------------------------------

def cmd_logout(auth_path: str = AUTH_PATH):
    """Revoke the refresh token, then clear tokens locally (profiles-and-sessions)."""
    auth = AuthManager(auth_path)
    with _file_lock(auth_path):
        auth.data = auth._load()
        refresh_token = auth.data.get("refresh_token")
        if not refresh_token:
            print("Not signed in.")
            return
        confirmed = False
        endpoint = fetch_discovery()["revocation_endpoint"]
        for attempt in range(3):
            try:
                resp = httpx.post(endpoint, timeout=30, data={
                    "token":           refresh_token,
                    "token_type_hint": "refresh_token",
                    "client_id":       auth.data["client_id"],
                })
                if resp.status_code == 200:
                    confirmed = True
                    break
                if resp.status_code < 500:
                    print(f"Revocation returned HTTP {resp.status_code}.", file=sys.stderr)
                    break
            except httpx.TransportError:
                pass
            time.sleep(2 ** attempt)
        auth.clear_tokens()
        auth.save()
    if confirmed:
        print("Signed out. The session was revoked.")
    else:
        print("Signed out locally, but remote revocation was not confirmed.\n"
              f"You can disconnect the app in ChatGPT Settings ({USAGE_URL}).")


# --- list / test ------------------------------------------------------------

def list_models(auth: AuthManager) -> list[dict]:
    """GET /v1/models; keep `visibility == "list"` in server order (models-and-inference §1).

    The body has `models[]` with `slug`/`display_name`, not the standard `data[]`,
    so the raw response is parsed.
    """
    raw = auth.make_client().models.with_raw_response.list()
    data = json.loads(raw.text)
    return [m for m in data.get("models", []) if m.get("visibility") == "list"]


def cmd_list(auth: AuthManager):
    models = list_models(auth)
    for m in models:
        print(f"{m['slug']:30} {m.get('display_name', '')}")


def cmd_test(auth: AuthManager, model: str | None, prompt: str, effort: str | None):
    """Stream one Responses request (models-and-inference §2-§3).

    `store=False` and `stream=True` are required. Only parameters not listed as
    unsupported in preview-limitations are used; the system prompt goes in
    `instructions` (system-role message items are rejected).
    """
    if model is None:
        models = list_models(auth)
        if not models:
            raise InferenceError("no_models", "The account has no listed models.")
        model = models[-1]["slug"]  # the last listed model tends to be the lightest
    print(f"Model: {model}  (Using ChatGPT plan — manage usage: {USAGE_URL})")

    request = {
        "model":        model,
        "instructions": "You are a helpful assistant.",
        "input":        [{"role": "user", "content": prompt}],
        "store":        False,
        "stream":       True,
    }
    if effort:
        request["reasoning"] = {"effort": effort, "summary": "auto"}

    completed = None
    in_reasoning = in_answer = False
    with auth.make_client().responses.create(**request) as stream:
        for event in stream:
            match event.type:
                case "response.reasoning_summary_text.delta":
                    if not in_reasoning:
                        print("[Thinking]", flush=True)
                        in_reasoning = True
                    print(event.delta, end="", flush=True)
                case "response.reasoning_summary_text.done":
                    print()
                    in_reasoning = False
                case "response.output_text.delta":
                    if not in_answer:
                        print("[Answer]", flush=True)
                        in_answer = True
                    print(event.delta, end="", flush=True)
                case "response.failed":
                    err = event.response.error
                    raise InferenceError(err.code if err else "unknown_error",
                                         err.message if err else "")
                case "response.incomplete":
                    details = event.response.incomplete_details
                    raise InferenceError("incomplete", details.reason if details else "")
                case "error":
                    raise InferenceError(event.code or "error", event.message, event.param)
                case "response.completed":
                    completed = event.response
    print()
    if completed is None:
        raise InferenceError("interrupted", "Stream ended without response.completed.")
    _print_usage(completed.usage)


def _print_usage(usage):
    """Token usage of this one request. Remaining plan limits are not available
    through the API; they are shown only in ChatGPT settings (profiles-and-sessions)."""
    if usage is None:
        print("Usage: (not reported)")
        return
    cached = getattr(usage.input_tokens_details, "cached_tokens", None)
    reasoning = getattr(usage.output_tokens_details, "reasoning_tokens", None)
    line = f"Usage: input {usage.input_tokens}"
    if cached:
        line += f" (cached {cached})"
    line += f", output {usage.output_tokens}"
    if reasoning:
        line += f" (reasoning {reasoning})"
    line += f", total {usage.total_tokens} tokens"
    print(line)
    print(f"Remaining plan limits: see {USAGE_URL}")


def _describe_api_error(e: APIStatusError) -> str:
    """Preserve status, error code, and request ID (errors-and-recovery)."""
    body = e.body if isinstance(e.body, dict) else {}
    nested = body.get("error") if isinstance(body.get("error"), dict) else {}
    code = body.get("code") or nested.get("code")
    param = body.get("param") or nested.get("param")
    detail = body.get("message") or nested.get("message") or body.get("detail") or e.message
    lines = [f"HTTP {e.status_code}" + (f" {code}" if code else "") + f": {detail}"]
    if param:
        lines.append(f"param: {param}")
    if code in ERROR_HINTS:
        lines.append(ERROR_HINTS[code])
    elif e.status_code == 401:
        lines.append("Identity or plan permission was not accepted. Check the account and granted scopes.")
    elif e.status_code == 403:
        lines.append("A policy or permission check (e.g. serving region) prevented the request.")
    elif e.status_code == 503:
        lines.append("Direct routing is unavailable. Try again later.")
    if e.request_id:
        lines.append(f"request_id: {e.request_id}")
    return "\n".join(lines)


# --- CLI --------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign in with ChatGPT (plan usage) sample")
    sub = parser.add_subparsers(dest="command", required=True)
    p_login = sub.add_parser("login", help="Sign in with ChatGPT")
    p_login.add_argument("--consent", action="store_true",
                         help="ask for consent again (e.g. to enable plan usage after declining)")
    sub.add_parser("logout", help="revoke the session and clear tokens")
    sub.add_parser("list", help="list available models")
    p_test = sub.add_parser("test", help="stream a test request")
    p_test.add_argument("-m", "--model", help="model slug (default: last listed model)")
    p_test.add_argument("-p", "--prompt", default="What is your name?")
    p_test.add_argument("--effort", help="reasoning effort; also shows the reasoning summary")
    args = parser.parse_args(argv)

    try:
        if args.command == "login":
            cmd_login(consent=args.consent)
        elif args.command == "logout":
            cmd_logout()
        else:
            auth = AuthManager()
            if args.command == "list":
                auth.auto_refresh(cmd_list)
            elif args.command == "test":
                auth.auto_refresh(cmd_test, args.model, args.prompt, args.effort)
    except (LoginRequired, PlanUsageDisabled, OAuthError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 1
    except InferenceError as e:
        print(f"\nInference failed: {e}", file=sys.stderr)
        if e.param:
            print(f"param: {e.param}", file=sys.stderr)
        if e.code in ERROR_HINTS:
            print(ERROR_HINTS[e.code], file=sys.stderr)
        return 1
    except APIStatusError as e:
        print(f"\n{_describe_api_error(e)}", file=sys.stderr)
        return 1
    except jwt.PyJWTError as e:
        print(f"\nID token validation failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
