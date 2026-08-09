"""MCP over Streamable HTTP — the same tools, reachable without a local process.

The stdio adapter (adapters/mcp_stdio.py) ships standalone and keeps its own copy
of the catalog on purpose: it must run on a machine that has nothing but python3.
`test_mcp_parity` pins the two copies together so they cannot drift.
"""
from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any

from fastapi import HTTPException

from .schemas import EditIn, InlineBlobIn, SendIn, SessionIn

PROTOCOL = "2024-11-05"

_STR = {"type": "string"}


def _tool(name, description, properties=None, required=None):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties or {},
                            "required": required or []}}


CATALOG = [
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


def build_ops(routes: dict[str, Any]) -> dict:
    """Bind tool names to the very functions the HTTP routes use.

    Not a reimplementation: the same code path, so a rule enforced for an HTTP
    caller is enforced for an MCP caller by construction.
    """
    r = routes
    return {
        "whoami": lambda a, req, p: r["me"](req, p),
        "directory_list": lambda a, req, p: r["directory"](req, p),
        "send": lambda a, req, p: r["send"](SendIn(**a), req, p),
        "session_open": lambda a, req, p: r["open_session"](SessionIn(**a), req, p),
        "session_list": lambda a, req, p: r["list_sessions"](req, p, chat=a.get("chat")),
        "inbox_list": lambda a, req, p: r["list_messages"](
            req, p, box=a.get("box", "inbox"), session=a.get("session"),
            limit=a.get("limit") or 50, before=None),
        "message_read": lambda a, req, p: r["read_message"](
            a["id"], req, p, peek=bool(a.get("peek"))),
        "archive": lambda a, req, p: r["archive"](a["id"], req, p),
        "sent_status": lambda a, req, p: r["message_status"](a["id"], req, p),
        "unsend": lambda a, req, p: r["unsend"](a["id"], req, p),
        "edit": lambda a, req, p: r["edit"](a["id"], EditIn(body=a["new_body"]), req, p),
        "attach_file": lambda a, req, p: r["upload_blob_inline"](
            InlineBlobIn(filename=a.get("filename") or "fichier",
                         content_base64=a["content_base64"],
                         content_type=a.get("content_type")), req, p),
        "attachment_read": lambda a, req, p: r["read_attachment"](
            a["message_id"], a["blob_id"], req, p),
        "thread_read": lambda a, req, p: r["read_thread"](a["thread_id"], req, p),
        "wait_for_message": lambda a, req, p: r["events"](
            req, p, since=int(a.get("since", 0)),
            timeout=float(a.get("timeout", 25.0))),
    }


async def dispatch(body: dict, request, principal, server_info: dict) -> dict | None:
    """One JSON-RPC message in, one response out (None for notifications)."""
    method, rid = body.get("method"), body.get("id")

    if method == "initialize":
        asked = (body.get("params") or {}).get("protocolVersion")
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": asked or PROTOCOL,
            "capabilities": {"tools": {}}, "serverInfo": server_info}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method and method.startswith("notifications/"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": CATALOG}}
    if method == "tools/call":
        params = body.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        op = request.app.state.mcp_ops.get(name)
        if op is None:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": f"tool inconnu: {name}"}}
        try:
            # The ops are synchronous database work, and this endpoint is async:
            # running them inline would do that work *in the event loop*. Mostly
            # invisible — queries take microseconds — but `attach_file` decodes
            # and writes up to a megabyte, which stalls every other caller for
            # as long as it takes. A thread costs nothing here and removes the
            # whole class.
            result = await asyncio.to_thread(op, args, request, principal)
            if inspect.isawaitable(result):
                result = await result
            is_error = False
        except HTTPException as e:
            result = {"error": {"status": e.status_code, "detail": e.detail}}
            is_error = True
        except Exception as e:
            result = {"error": {"status": 400, "detail": f"{e.__class__.__name__}: {e}"}}
            is_error = True
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text",
                         "text": json.dumps(result, ensure_ascii=False, indent=2, default=str)}],
            "isError": is_error}}

    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"méthode inconnue: {method}"}}
    return None
