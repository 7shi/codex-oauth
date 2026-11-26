"""Sign-in, reauthorization, refresh and sign-out flows against mocked OpenAI endpoints.

The token endpoint, discovery and JWKS are mocked (ID tokens are signed with a local
RSA key); the pasted callback URL is simulated by patching input().
"""
import contextlib
import io
import json
import os
import stat
import sys
import time
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import codex_oauth as co

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISS = "https://auth.openai.com"
ISSUED = "oaiapp_TEST123"
REDIRECT = "http://127.0.0.1:1455/auth/callback"


def make_id_token(aud=ISSUED, nonce=None, sub="user-1", exp=3600):
    now = int(time.time())
    claims = {"iss": ISS, "sub": sub, "aud": [aud], "iat": now, "exp": now + exp,
              "email": "a@example.com", "email_verified": True}
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(claims, KEY, algorithm="RS256")


class FakeJWKClient:
    def get_signing_key_from_jwt(self, token):
        return type("Key", (), {"key": KEY.public_key()})()


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Isolated working directory and mocked endpoints. Returns the scenario dict:
    set keys before calling run() to change how the mocks behave."""
    monkeypatch.chdir(tmp_path)
    sc = {"token_calls": []}
    monkeypatch.setattr(co, "fetch_discovery", lambda: {
        "issuer": ISS, "jwks_uri": "x", "revocation_endpoint": "https://rev",
        "id_token_signing_alg_values_supported": ["RS256"]})
    monkeypatch.setattr(co, "_jwks_client", lambda uri: FakeJWKClient())

    def fake_input(prompt=""):
        # run() redirects stdout to a StringIO; read the authorization URL printed by login.
        url = next(line.strip() for line in sys.stdout.getvalue().splitlines()
                   if line.startswith(co.AUTHORIZE_URL))
        p = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        sc["auth_params"] = p
        cb = {"state": "evil" if sc.get("tamper") else p["state"], "code": "CODE1"}
        if sc.get("deny"):
            cb = {"state": p["state"], "error": "access_denied"}
        if p["client_id"] == co.REGISTRATION_CLIENT_ID:
            cb["client_id"] = ISSUED
        if sc.get("other_client"):
            cb["client_id"] = "oaiapp_OTHER"
        query = urlencode(cb)
        if sc.get("query_only"):
            return query
        if sc.get("wrong_base"):
            return "http://localhost:1455/auth/callback?" + query
        return p["redirect_uri"] + "?" + query

    monkeypatch.setattr("builtins.input", fake_input)

    def fake_post_token(data):
        sc["token_calls"].append(data)
        if sc.get("refresh_error") and data["grant_type"] == "refresh_token":
            raise co.OAuthError("HTTP 400", sc["refresh_error"])
        n = len(sc["token_calls"])
        resp = {"access_token": f"AT-SECRET-{n}", "refresh_token": f"RT-SECRET-{n}",
                "token_type": "Bearer", "expires_in": 3600,
                "scope": sc.get("scope", " ".join(co.SCOPES))}
        if data["grant_type"] == "authorization_code":
            resp["id_token"] = make_id_token(nonce=sc["auth_params"]["nonce"], sub=sc.get("sub", "user-1"))
        return resp

    monkeypatch.setattr(co, "_post_token", fake_post_token)
    return sc


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = co.main(argv)
    return rc, out.getvalue()


def login(sc, **options):
    """Run `login` with fresh mock options; returns (rc, output, authorize params)."""
    for k in ("tamper", "deny", "other_client", "query_only", "wrong_base", "sub", "scope"):
        sc.pop(k, None)
    sc.update(options)
    sc["token_calls"].clear()
    rc, out = run(["login"] + (["--consent"] if options.get("consent") else []))
    return rc, out, sc.get("auth_params", {})


def saved():
    with open("auth.json") as f:
        return json.load(f)


def expire():
    data = saved()
    data["saved_at"] = "2000-01-01T00:00:00Z"
    with open("auth.json", "w") as f:
        json.dump(data, f)


# --- registration / reauthorization -----------------------------------------

def test_old_format_is_rejected(env):
    with open("auth.json", "w") as f:
        json.dump({"type": "oauth", "access": "x", "refresh": "y", "expires": 1}, f)
    rc, out = run(["list"])
    assert rc == 1 and "old Codex" in out
    rc, out, _ = login(env)
    assert rc == 0 and os.path.exists("auth.json.old")


def test_first_registration(env):
    rc, out, p = login(env)
    assert rc == 0
    assert p["client_id"] == "dynamic_agent_client"
    assert p["agent_name_hint"] == "codex-oauth"
    assert p["redirect_uri"] == REDIRECT
    assert p["scope"] == " ".join(co.SCOPES)
    assert p["resource"] == "https://api.openai.com/v1"
    assert p["code_challenge_method"] == "S256" and p["nonce"] and p["state"]
    assert p["ext_agent_host_id"].startswith("urn:uuid:")
    exchange = env["token_calls"][0]
    assert exchange["client_id"] == ISSUED
    assert exchange["redirect_uri"] == REDIRECT
    assert exchange["resource"] == co.RESOURCE
    data = saved()
    assert data["client_id"] == ISSUED and data["subject"] == "user-1"
    assert stat.S_IMODE(os.stat("auth.json").st_mode) == 0o600
    assert stat.S_IMODE(os.stat("host.json").st_mode) == 0o600
    assert "SECRET" not in out and "eyJ" not in out


def test_reauthorization_reuses_client_and_host(env):
    _, _, first = login(env)
    rc, out, p = login(env)
    assert rc == 0
    assert p["client_id"] == ISSUED
    assert p["ext_agent_host_id"] == first["ext_agent_host_id"]
    assert "agent_name_hint" not in p and "id_token_hint" not in p
    assert p["login_hint"] == "a@example.com"
    assert "SECRET" not in out and "eyJ" not in out


def test_bare_query_string_is_accepted(env):
    rc, _, _ = login(env, query_only=True)
    assert rc == 0


def test_wrong_redirect_base_is_rejected(env):
    rc, out, _ = login(env, wrong_base=True)
    assert rc == 1 and "does not start with" in out


def test_different_client_id_is_rejected(env):
    login(env)
    rc, out, _ = login(env, other_client=True)
    assert rc == 1 and "different client_id" in out
    assert saved()["client_id"] == ISSUED


def test_different_account_is_rejected(env):
    login(env)
    rc, out, _ = login(env, sub="user-2")
    assert rc == 1 and "different account" in out
    assert saved()["subject"] == "user-1"


def test_state_mismatch(env):
    rc, out, _ = login(env, tamper=True)
    assert rc == 1 and "state mismatch" in out
    assert not os.path.exists("auth.json")


def test_access_denied(env):
    rc, out, _ = login(env, deny=True)
    assert rc == 1 and "declined" in out
    assert not os.path.exists("auth.json")


def test_plan_scope_missing_then_consent(env):
    rc, out, _ = login(env, scope="openid profile email offline_access")
    assert rc == 0 and "not granted" in out
    rc, out = run(["test"])
    assert rc == 1 and "--consent" in out
    rc, _, p = login(env, consent=True)
    assert rc == 0 and p["prompt"] == "consent"


# --- refresh / sign-out ------------------------------------------------------

def test_refresh_rotates_tokens(env):
    login(env)
    expire()
    env["token_calls"].clear()
    co.AuthManager().ensure_valid()
    form = env["token_calls"][0]
    assert form["grant_type"] == "refresh_token"
    assert form["client_id"] == ISSUED
    assert form["resource"] == co.RESOURCE
    assert "scope" not in form
    assert saved()["refresh_token"] == "RT-SECRET-1"
    assert stat.S_IMODE(os.stat("auth.json").st_mode) == 0o600


def test_terminal_refresh_error_clears_tokens(env):
    login(env)
    expire()
    env["refresh_error"] = "refresh_token_reused"
    with pytest.raises(co.LoginRequired):
        co.AuthManager().ensure_valid()
    data = saved()
    assert "refresh_token" not in data and data["client_id"] == ISSUED
    env.pop("refresh_error")
    rc, _, p = login(env)
    assert rc == 0 and p["client_id"] == ISSUED


def test_temporary_refresh_error_keeps_tokens(env):
    login(env)
    expire()
    env["refresh_error"] = "server_error"
    with pytest.raises(co.OAuthError):
        co.AuthManager().ensure_valid()
    assert saved()["refresh_token"] == "RT-SECRET-1"


def test_logout_revokes_and_keeps_registration(env, monkeypatch):
    login(env)
    posted = {}

    def fake_post(url, data=None, **kwargs):
        posted.update(data, url=url)
        return httpx.Response(200)

    monkeypatch.setattr(co.httpx, "post", fake_post)
    rc, out = run(["logout"])
    assert rc == 0 and "revoked" in out
    assert posted["url"] == "https://rev"
    assert posted["token"] == "RT-SECRET-1"
    assert posted["token_type_hint"] == "refresh_token"
    assert posted["client_id"] == ISSUED
    data = saved()
    assert "access_token" not in data and data["client_id"] == ISSUED
    rc, out = run(["test"])
    assert rc == 1 and "Not signed in" in out


# --- ID token validation -----------------------------------------------------

@pytest.mark.parametrize("token_args", [
    {"aud": "oaiapp_OTHER", "nonce": "N1"},
    {"nonce": "other"},
    {"nonce": "N1", "exp": -100},
], ids=["audience", "nonce", "expired"])
def test_invalid_id_token_is_rejected(env, token_args):
    with pytest.raises((jwt.PyJWTError, co.OAuthError)):
        co.verify_id_token(make_id_token(**token_args), ISSUED, "N1")
