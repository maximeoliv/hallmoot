#!/usr/bin/env python3
"""End-to-end smoke test against a running instance.

Run: python3 scripts/smoke.py [base_url]

Secrets discipline: invite codes and chat tokens are read/held in memory and
never printed. The script prints check names and verdicts, nothing else.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import _env

BASE = (sys.argv[1] if len(sys.argv) > 1 else _env.api_url()).rstrip("/")
OWNER = Path(__file__).resolve().parent.parent / "data" / "owner-token"

results: list[tuple[str, bool, str]] = []


def call(method: str, path: str, token: str | None = None, body: dict | None = None):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
    )
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))


def enroll(owner: str, handle: str) -> tuple[str, str]:
    _, inv = call("POST", "/v1/admin/invites", owner, {"note": handle})
    _, reg = call("POST", "/v1/register", None, {
        "invite_code": inv["invite_code"], "handle": handle,
        "display_name": handle, "client": "smoke"})
    return reg["chat_id"], reg["chat_token"]


def main() -> int:
    owner = OWNER.read_text().strip()
    suffix = str(int(time.time()))[-6:]
    a_id, a = enroll(owner, f"smoke-a-{suffix}")
    b_id, b = enroll(owner, f"smoke-b-{suffix}")
    check("enrôlement de deux chats via invitation", bool(a and b))

    st, me = call("GET", "/v1/me", a)
    check("identité dérivée du jeton", st == 200 and me["id"] == a_id)

    st, dir_ = call("GET", "/v1/directory", a)
    handles = {c["handle"] for c in dir_["chats"]}
    check("annuaire: chacun voit l'autre",
          {f"smoke-a-{suffix}", f"smoke-b-{suffix}"} <= handles)

    st, sent = call("POST", "/v1/messages", a, {
        "to": f"smoke-b-{suffix}", "subject": "ping", "body": "premier message"})
    mid = sent.get("id")
    check("envoi a → b", st == 201 and bool(mid))

    st, inbox = call("GET", "/v1/messages", b)
    check("le message arrive dans l'inbox de b", inbox["count"] == 1)

    st, msg = call("GET", f"/v1/messages/{mid}", b)
    check("`from` non falsifiable", msg["from"] == f"smoke-a-{suffix}")

    st, status = call("GET", f"/v1/messages/{mid}/status", a)
    check("statut delivered → read après lecture",
          status["deliveries"][0]["status"] == "read")

    st, m2 = call("POST", "/v1/messages", a, {
        "to": f"smoke-b-{suffix}", "subject": "oops", "body": "à rappeler"})
    st, _ = call("DELETE", f"/v1/messages/{m2['id']}", a)
    check("unsend avant lecture", st == 200)
    st, _ = call("GET", f"/v1/messages/{m2['id']}", b)
    check("le message rappelé n'est plus lisible", st == 410)

    st, recall_late = call("DELETE", f"/v1/messages/{mid}", a)
    check("unsend refusé après lecture",
          st == 409 and recall_late["detail"]["reason"] == "already_read")

    st, reply = call("POST", "/v1/messages", b, {
        "to": f"smoke-a-{suffix}", "subject": "re: ping", "body": "pong",
        "in_reply_to": mid})
    check("réponse dans le même fil", reply.get("thread_id") == sent.get("thread_id"))
    st, status = call("GET", f"/v1/messages/{mid}/status", a)
    check("statut passe à replied", status["deliveries"][0]["status"] == "replied")

    st, thread = call("GET", f"/v1/threads/{sent['thread_id']}", a)
    check("fil reconstruit dans l'ordre",
          [m["body"] for m in thread["messages"]] == ["premier message", "pong"])

    st, ev = call("GET", "/v1/events?since=0&timeout=0", b)
    check("events signalent le courrier",
          any(e["type"] == "message.received" for e in ev["events"]))

    st, _ = call("GET", "/v1/admin/chats", a)
    check("un jeton de chat ne peut pas administrer", st == 403)

    st, listed = call("POST", "/mcp", a, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tools = {t["name"] for t in listed.get("result", {}).get("tools", [])}
    check("MCP HTTP: tools/list",
          st == 200 and {"send", "inbox_list", "session_open", "directory_list"} <= tools,
          f"{len(tools)} outils")
    st, called = call("POST", "/mcp", a, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}}})
    check("MCP HTTP: tools/call whoami",
          st == 200 and not called["result"]["isError"])

    for cid in (a_id, b_id):
        call("DELETE", f"/v1/admin/chats/{cid}", owner)
    st, _ = call("GET", "/v1/me", a)
    check("révocation: le jeton ne vaut plus rien", st == 401)

    width = max(len(n) for n, _, _ in results)
    failed = 0
    for name, ok, detail in results:
        failed += not ok
        print(f"  {'✓' if ok else '✗'}  {name.ljust(width)}  {detail}")
    print(f"\n{len(results) - failed}/{len(results)} checks OK sur {BASE}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
