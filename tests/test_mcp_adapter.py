"""The MCP adapter, driven exactly like a chat client drives it.

Not a mock: a real uvicorn process, a real adapter subprocess, real JSON-RPC
lines over stdin/stdout. The adapter's whole job is to be a faithful client of
the HTTP API, and the only way to know it is, is to run it.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
OWNER = "test-owner-token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post(url, body=None, token=None, method="POST"):
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(body).encode() if body else None)
    if body:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"{}")


@pytest.fixture(scope="module")
def instance(tmp_path_factory):
    """A real instance on loopback, torn down at the end of the module."""
    port = _free_port()
    env = {**os.environ,
           "MOOT_DB_PATH": str(tmp_path_factory.mktemp("mcp") / "db.sqlite3"),
           "MOOT_OWNER_TOKEN": OWNER,
           "PYTHONPATH": str(ROOT)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.asgi:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            break
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("the instance never came up")
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def _enroll(base, handle):
    inv = _post(f"{base}/v1/admin/invites", {"note": handle}, OWNER)
    return _post(f"{base}/v1/register", {
        "invite_code": inv["invite_code"], "handle": handle,
        "display_name": handle, "client": "pytest-mcp"})


class Adapter:
    """Drives the adapter over stdio, the way an MCP client does."""

    def __init__(self, base, token):
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "adapters" / "mcp_stdio.py")],
            env={**os.environ, "MOOT_API_URL": base, "MOOT_TOKEN": token},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self._id = 0

    def rpc(self, method, params=None):
        self._id += 1
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method,
             "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def call(self, tool, **args):
        res = self.rpc("tools/call", {"name": tool, "arguments": args})
        return json.loads(res["result"]["content"][0]["text"]), res["result"].get("isError")

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


@pytest.fixture(scope="module")
def peers(instance):
    a = _enroll(instance, "cowork")
    b = _enroll(instance, "desktop")
    ad_a, ad_b = Adapter(instance, a["chat_token"]), Adapter(instance, b["chat_token"])
    yield ad_a, ad_b
    ad_a.close()
    ad_b.close()


def test_handshake_and_tool_list(peers):
    ad_a, _ = peers
    init = ad_a.rpc("initialize", {"protocolVersion": "2025-06-18"})
    assert init["result"]["protocolVersion"] == "2025-06-18"  # we echo the client's
    tools = {t["name"] for t in ad_a.rpc("tools/list")["result"]["tools"]}
    assert {"whoami", "directory_list", "send", "inbox_list", "message_read",
            "archive", "sent_status", "unsend", "edit", "thread_read",
            "wait_for_message", "session_open", "session_list", "attach_file",
            "attachment_read"} == tools


def test_whoami_and_directory(peers):
    ad_a, _ = peers
    me, err = ad_a.call("whoami")
    assert not err and me["handle"] == "cowork"
    directory, _ = ad_a.call("directory_list")
    assert {c["handle"] for c in directory["chats"]} == {"cowork", "desktop"}


def test_full_conversation_through_the_adapter(peers):
    """The Phase 1 acceptance run, played entirely through MCP tools."""
    ad_a, ad_b = peers

    sent, err = ad_a.call("send", to="@desktop", subject="hello",
                          body="premier message depuis Cowork")
    assert not err and sent["delivered_to"] == ["desktop"]

    inbox, _ = ad_b.call("inbox_list")
    assert inbox["count"] == 1 and inbox["messages"][0]["from"] == "cowork"

    read, _ = ad_b.call("message_read", id=sent["id"])
    assert read["body"] == "premier message depuis Cowork"

    status, _ = ad_a.call("sent_status", id=sent["id"])
    assert status["deliveries"][0]["status"] == "read"

    reply, _ = ad_b.call("send", to="@cowork", subject="re: hello",
                         body="bien reçu", in_reply_to=sent["id"])
    thread, _ = ad_a.call("thread_read", thread_id=sent["thread_id"])
    assert [m["body"] for m in thread["messages"]] == [
        "premier message depuis Cowork", "bien reçu"]
    assert reply["thread_id"] == sent["thread_id"]

    archived, err = ad_b.call("archive", id=sent["id"])
    assert not err and archived["archived"]
    emptied, _ = ad_b.call("inbox_list")
    assert emptied["count"] == 0


def test_unsend_and_edit_semantics_survive_the_adapter(peers):
    ad_a, ad_b = peers
    m, _ = ad_a.call("send", to="@desktop", subject="oops", body="typo")

    edited, err = ad_a.call("edit", id=m["id"], new_body="corrigé")
    assert not err and edited["edited"]

    recalled, err = ad_a.call("unsend", id=m["id"])
    assert not err and recalled["recalled"]

    m2, _ = ad_a.call("send", to="@desktop", subject="lu", body="celui-là sera lu")
    ad_b.call("message_read", id=m2["id"])
    refused, err = ad_a.call("unsend", id=m2["id"])
    assert err is True and refused["error"]["status"] == 409
    assert refused["error"]["detail"]["reason"] == "already_read"


def test_errors_are_reported_not_swallowed(peers):
    ad_a, _ = peers
    missing, err = ad_a.call("message_read", id="00000000-0000-7000-8000-000000000000")
    assert err is True and missing["error"]["status"] == 404

    unknown = ad_a.rpc("tools/call", {"name": "rm_rf", "arguments": {}})
    assert unknown["error"]["code"] == -32601

    bad, err = ad_a.call("send", to="@ghost", subject="s", body="b")
    assert err is True and bad["error"]["status"] == 400


def test_wait_for_message_returns_the_event(peers):
    ad_a, ad_b = peers
    before, _ = ad_b.call("wait_for_message", since=0, timeout=0)
    cursor = before["cursor"]
    sent, _ = ad_a.call("send", to="@desktop", subject="ping", body="nouveau")
    events, err = ad_b.call("wait_for_message", since=cursor, timeout=2)
    assert not err
    assert any(e["message_id"] == sent["id"] and e["type"] == "message.received"
               for e in events["events"])
