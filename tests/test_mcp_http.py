"""MCP over Streamable HTTP — the surface Phase 1.5 will expose to the outside.

Also the parity guard: the standalone stdio adapter carries its own copy of the
tool catalog so it can run anywhere with nothing installed. Duplication is fine
as long as it cannot drift silently — that is what test_catalogs_match is for.
"""
import importlib.util
import json
from pathlib import Path

from app.mcp import CATALOG

ROOT = Path(__file__).resolve().parent.parent


def _load_adapter():
    spec = importlib.util.spec_from_file_location(
        "mcp_stdio", ROOT / "adapters" / "mcp_stdio.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rpc(client, headers, method, params=None, rid=1):
    return client.post("/mcp", headers=headers,
                       json={"jsonrpc": "2.0", "id": rid, "method": method,
                             "params": params or {}})


def call(client, headers, tool, **args):
    res = rpc(client, headers, "tools/call", {"name": tool, "arguments": args})
    payload = res.json()["result"]
    return json.loads(payload["content"][0]["text"]), payload["isError"]


def test_catalogs_match(client):
    """The stdio adapter and the HTTP endpoint must offer the same tools."""
    adapter = _load_adapter()
    assert {t["name"]: t["inputSchema"] for t in adapter.TOOLS} == \
           {t["name"]: t["inputSchema"] for t in CATALOG}
    assert {t["name"]: t["description"] for t in adapter.TOOLS} == \
           {t["name"]: t["description"] for t in CATALOG}


def test_mcp_requires_a_token(client):
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"}).status_code == 401


def test_handshake_and_catalog(client, alice):
    init = rpc(client, alice["headers"], "initialize",
               {"protocolVersion": "2025-06-18"}).json()
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert init["result"]["capabilities"] == {"tools": {}}

    listed = rpc(client, alice["headers"], "tools/list").json()
    assert {t["name"] for t in listed["result"]["tools"]} == {t["name"] for t in CATALOG}


def test_notifications_get_no_answer(client, alice):
    res = client.post("/mcp", headers=alice["headers"],
                      json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert res.status_code == 202


def test_a_conversation_over_http_mcp(client, alice, bob):
    sent, err = call(client, alice["headers"], "send",
                     to="@bob", subject="hello", body="par MCP HTTP")
    assert not err

    inbox, _ = call(client, bob["headers"], "inbox_list")
    assert inbox["count"] == 1 and inbox["messages"][0]["from"] == "alice"

    read, _ = call(client, bob["headers"], "message_read", id=sent["id"])
    assert read["body"] == "par MCP HTTP"

    status, _ = call(client, alice["headers"], "sent_status", id=sent["id"])
    assert status["deliveries"][0]["status"] == "read"


def test_the_rules_hold_on_the_mcp_path_too(client, alice, bob, mallory):
    """MCP is not a side door: same checks, because it is the same code path."""
    sent, _ = call(client, alice["headers"], "send",
                   to="@bob", subject="private", body="secret")

    peeked, err = call(client, mallory["headers"], "message_read", id=sent["id"])
    assert err and peeked["error"]["status"] == 404

    client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"])  # bob reads
    recalled, err = call(client, alice["headers"], "unsend", id=sent["id"])
    assert err and recalled["error"]["status"] == 409

    unknown = rpc(client, alice["headers"], "tools/call",
                  {"name": "drop_database", "arguments": {}}).json()
    assert unknown["error"]["code"] == -32601


def test_wait_for_message_over_http(client, alice, bob):
    sent, _ = call(client, alice["headers"], "send", to="@bob", subject="s", body="b")
    events, err = call(client, bob["headers"], "wait_for_message", since=0, timeout=0)
    assert not err
    assert any(e["message_id"] == sent["id"] for e in events["events"])


def test_get_mcp_is_not_a_stream(client, alice):
    assert client.get("/mcp", headers=alice["headers"]).status_code == 405
