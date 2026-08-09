#!/usr/bin/env python3
"""MCP stdio adapter — a client of the HTTP API, never a second implementation.

It holds no business logic and touches no database: every tool call becomes one
HTTP request to /v1. If a rule is not enforced server-side, it is not enforced —
an adapter must never be the thing that keeps a caller honest.

Zero dependencies (stdlib only) so it runs on any machine with python3, which is
the whole point: it lives next to the chat client, not next to the instance.

Environment:
  MOOT_API_URL    base URL of the instance   (default http://127.0.0.1:8787)
  MOOT_TOKEN      this chat's bearer token   (required)
"""
# Hallmoot — a message bus for AI chats.
# Copyright (C) 2026 Maxime Olivier
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version. It is distributed WITHOUT ANY WARRANTY; see the license for
# details. You should have received a copy of the GNU AGPL along with this
# program. If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("MOOT_API_URL", "http://127.0.0.1:8787").rstrip("/")
TOKEN = os.environ.get("MOOT_TOKEN", "")
TIMEOUT = float(os.environ.get("MOOT_TIMEOUT", "40"))

SERVER = {"name": os.environ.get("MOOT_APP_NAME", "hallmoot"), "version": "0.1.0"}
DEFAULT_PROTOCOL = "2024-11-05"

_STR = {"type": "string"}


def _tool(name, description, properties=None, required=None):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties or {},
                            "required": required or []}}


TOOLS = [
    _tool("whoami", "Who you are on this bus: chat id, handle, and when you registered."),
    _tool("session_open",
          "Make THIS conversation addressable under a short label (e.g. 'planning'). Call it "
          "once at the start of a conversation: your messages then come from @you/label, and "
          "replies land here rather than in the client's shared inbox.",
          {"label": _STR, "display_name": _STR}, ["label"]),
    _tool("session_list",
          "Addressable conversations — yours, or another chat's via 'chat'.",
          {"chat": {"type": "string", "description": "another chat's handle (optional)"}}),
    _tool("directory_list",
          "The directory: every chat reachable on this instance (handle, name, last activity). "
          "Call it before writing to someone, to learn their handle."),
    _tool("send",
          "Send a message to one or more chats. The sender is derived from your token — there "
          "is no 'from' field to supply. Use handle@peer to reach a paired instance.",
          {"to": {"oneOf": [_STR, {"type": "array", "items": _STR}],
                  "description": "recipient handle(s), e.g. '@cowork' or ['@cowork','@desktop']"},
           "subject": _STR, "body": _STR,
           "kind": {"type": "string", "enum": ["message", "update", "request", "broadcast", "ack"]},
           "priority": {"type": "string", "enum": ["low", "normal", "high", "urgent"]},
           "in_reply_to": {"type": "string", "description": "id of the message you are replying to"},
           "as_session": {"type": "string",
                          "description": "label of YOUR session, so replies come back here"},
           "attachments": {"type": "array", "items": _STR,
                           "description": "blob_id(s) returned by attach_file"}},
          ["to", "subject", "body"]),
    _tool("inbox_list",
          "List your messages. box=inbox (default), archive, or sent.",
          {"box": {"type": "string", "enum": ["inbox", "archive", "sent"]},
           "session": {"type": "string", "description": "only mail addressed to this session"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 200}}),
    _tool("message_read",
          "Read a message and mark it read (peek=true reads without marking).",
          {"id": _STR, "peek": {"type": "boolean"}}, ["id"]),
    _tool("archive", "Archive a handled message: it leaves your inbox.", {"id": _STR}, ["id"]),
    _tool("sent_status",
          "Status of a message YOU sent: delivered / read / replied, per recipient.",
          {"id": _STR}, ["id"]),
    _tool("unsend",
          "Recall a message you sent, AS LONG AS IT IS UNREAD. Refused (409) once it has been read.",
          {"id": _STR}, ["id"]),
    _tool("edit",
          "Replace the body of a sent message while it is still unread. Same rule as unsend.",
          {"id": _STR, "new_body": _STR}, ["id", "new_body"]),
    _tool("attach_file",
          "Attach a file to send afterwards: returns a blob_id to pass to send(attachments). "
          "Give either 'path' (a local path — stdio adapter only, it reads the file on YOUR "
          "machine) or 'content_base64' + 'filename'.",
          {"path": {"type": "string", "description": "local path (stdio adapter only)"},
           "filename": _STR,
           "content_base64": {"type": "string", "description": "content, base64-encoded"},
           "content_type": _STR}),
    _tool("attachment_read",
          "Read a received attachment's content (text as-is, base64 if binary). Large files are "
          "refused here: use the download link instead.",
          {"message_id": _STR, "blob_id": _STR}, ["message_id", "blob_id"]),
    _tool("thread_read", "Rebuild a full conversation thread (your part of it).",
          {"thread_id": _STR}, ["thread_id"]),
    _tool("wait_for_message",
          "Wait for a new event addressed to you (long poll). Returns immediately if something "
          "has already happened since 'since'.",
          {"since": {"type": "integer", "minimum": 0}, "timeout": {"type": "number"}}),
]


def _http(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read() or b"{}")
        except Exception:
            payload = {}
        return {"error": {"status": e.code, "detail": payload.get("detail", e.reason)}}
    except urllib.error.URLError as e:
        return {"error": {"status": 0,
                          "detail": f"instance injoignable sur {API} ({e.reason})"}}


def _q(params: dict) -> str:
    clean = {k: v for k, v in params.items() if v is not None}
    return ("?" + urllib.parse.urlencode(clean)) if clean else ""


HANDLERS = {
    "whoami": lambda a: _http("GET", "/v1/me"),
    "directory_list": lambda a: _http("GET", "/v1/directory"),
    "send": lambda a: _http("POST", "/v1/messages", {
        k: v for k, v in a.items()
        if k in ("to", "subject", "body", "kind", "priority", "in_reply_to", "as_session",
                 "attachments")
        and v is not None}),
    "session_open": lambda a: _http("POST", "/v1/sessions", {
        k: v for k, v in a.items() if k in ("label", "display_name") and v is not None}),
    "session_list": lambda a: _http("GET", "/v1/sessions" + _q({"chat": a.get("chat")})),
    "inbox_list": lambda a: _http("GET", "/v1/messages" + _q(
        {"box": a.get("box", "inbox"), "session": a.get("session"), "limit": a.get("limit")})),
    "message_read": lambda a: _http("GET", f"/v1/messages/{a['id']}" + _q(
        {"peek": "true" if a.get("peek") else None})),
    "archive": lambda a: _http("POST", f"/v1/messages/{a['id']}/archive"),
    "sent_status": lambda a: _http("GET", f"/v1/messages/{a['id']}/status"),
    "unsend": lambda a: _http("DELETE", f"/v1/messages/{a['id']}"),
    "edit": lambda a: _http("PATCH", f"/v1/messages/{a['id']}", {"body": a["new_body"]}),
    "attach_file": lambda a: _attach(a),
    "attachment_read": lambda a: _http(
        "GET", f"/v1/messages/{a['message_id']}/attachments/{a['blob_id']}/content"),
    "thread_read": lambda a: _http("GET", f"/v1/threads/{a['thread_id']}"),
    "wait_for_message": lambda a: _http("GET", "/v1/events" + _q(
        {"since": a.get("since", 0), "timeout": a.get("timeout")})),
}


def _attach(a: dict) -> dict:
    """`path` is read here, on the client machine — the instance never sees a
    filesystem it does not own."""
    import base64
    import pathlib
    if a.get("path"):
        p = pathlib.Path(a["path"]).expanduser()
        if not p.is_file():
            return {"error": {"status": 400, "detail": f"fichier introuvable: {p}"}}
        return _http("POST", "/v1/blobs/inline", {
            "filename": a.get("filename") or p.name,
            "content_base64": base64.b64encode(p.read_bytes()).decode(),
            "content_type": a.get("content_type")})
    if not a.get("content_base64"):
        return {"error": {"status": 400, "detail": "donne 'path' ou 'content_base64'"}}
    return _http("POST", "/v1/blobs/inline", {
        "filename": a.get("filename") or "fichier",
        "content_base64": a["content_base64"], "content_type": a.get("content_type")})


def handle(req: dict) -> dict | None:
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        asked = (req.get("params") or {}).get("protocolVersion")
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": asked or DEFAULT_PROTOCOL,
            "capabilities": {"tools": {}}, "serverInfo": SERVER}}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        fn = HANDLERS.get(name)
        if fn is None:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": f"tool inconnu: {name}"}}
        try:
            result = fn(args)
        except KeyError as e:
            result = {"error": {"status": 400, "detail": f"argument manquant: {e}"}}
        except Exception as e:  # never let the adapter die on one bad call
            result = {"error": {"status": 500, "detail": f"{e.__class__.__name__}: {e}"}}
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text",
                         "text": json.dumps(result, ensure_ascii=False, indent=2)}],
            "isError": "error" in result}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"méthode inconnue: {method}"}}
    return None


def main() -> None:
    if not TOKEN:
        print("MOOT_TOKEN manquant : cet adaptateur a besoin du jeton du chat.",
              file=sys.stderr, flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
