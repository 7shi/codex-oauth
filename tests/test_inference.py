"""`list` and `test` against a mocked Responses API."""
import contextlib
import io
import json

import httpx
import pytest
from openai import OpenAI

import codex_oauth as co


def _response(status, **extra):
    return {"id": "r", "object": "response", "created_at": 0, "model": "m", "output": [],
            "parallel_tool_calls": True, "tool_choice": "auto", "tools": [], "status": status, **extra}


USAGE = {"input_tokens": 20, "input_tokens_details": {"cached_tokens": 0},
         "output_tokens": 15, "output_tokens_details": {"reasoning_tokens": 8}, "total_tokens": 35}


@pytest.fixture
def api(monkeypatch, tmp_path):
    """Signed-in AuthManager backed by a mock transport. Returns the mode dict:
    set "limit", "fail" or "cut" to change the response; "body" holds the last request."""
    monkeypatch.chdir(tmp_path)
    mode = {}

    def handler(req):
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"models": [
                {"slug": "hidden", "visibility": "hide"},
                {"slug": "m-1", "display_name": "M One", "visibility": "list"},
                {"slug": "m-2", "display_name": "M Two", "visibility": "list"}]})
        mode["body"] = json.loads(req.content)
        if mode.get("limit"):
            return httpx.Response(429, json={"error": {
                "code": "subscription_sharing_usage_limit_exceeded", "message": "limit",
                "type": "x", "param": None}})
        events = [{"type": "response.output_text.delta", "delta": "Hello", "item_id": "i",
                   "output_index": 0, "content_index": 0, "sequence_number": 1, "logprobs": []}]
        if mode.get("fail"):
            events.append({"type": "response.failed", "sequence_number": 2, "response": _response(
                "failed", error={"code": "subscription_sharing_usage_unavailable", "message": "x"})})
        elif not mode.get("cut"):
            events.append({"type": "response.completed", "sequence_number": 2,
                           "response": _response("completed", usage=USAGE)})
        sse = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events)
        return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})

    def fake_init(self, path="auth.json"):
        self.path = path
        self.data = {"access_token": "t", "refresh_token": "r", "scopes": co.SCOPES,
                     "saved_at": co._utc_now_iso(), "expires_in": 3600}
        self.make_client = lambda: OpenAI(
            api_key="t", base_url=co.API_BASE, max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)))

    monkeypatch.setattr(co.AuthManager, "__init__", fake_init)
    return mode


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = co.main(argv)
    return rc, out.getvalue()


def test_list_filters_and_keeps_order(api):
    rc, out = run(["list"])
    assert rc == 0
    assert "hidden" not in out
    assert out.index("m-1") < out.index("m-2")


def test_test_defaults_to_last_model(api):
    rc, out = run(["test"])
    body = api["body"]
    assert rc == 0
    assert body["model"] == "m-2"
    assert body["store"] is False and body["stream"] is True
    assert "instructions" in body
    assert not {"temperature", "max_output_tokens", "top_p", "metadata"} & set(body)
    assert "Hello" in out
    assert "input 20, output 15 (reasoning 8), total 35 tokens" in out
    assert co.USAGE_URL in out


def test_model_and_effort_options(api):
    rc, _ = run(["test", "-m", "m-1", "--effort", "low"])
    assert rc == 0
    assert api["body"]["model"] == "m-1"
    assert api["body"]["reasoning"] == {"effort": "low", "summary": "auto"}


def test_stream_without_completed_fails(api):
    api["cut"] = True
    rc, out = run(["test", "-m", "m-1"])
    assert rc == 1 and "interrupted" in out


def test_response_failed_reports_code(api):
    api["fail"] = True
    rc, out = run(["test", "-m", "m-1"])
    assert rc == 1
    assert "subscription_sharing_usage_unavailable" in out
    assert "Try again later" in out


def test_usage_limit_links_to_settings(api):
    api["limit"] = True
    rc, out = run(["test", "-m", "m-1"])
    assert rc == 1
    assert "HTTP 429" in out
    assert co.USAGE_URL in out
