#!/usr/bin/env python3
"""Enroll a chat and write its ready-to-paste MCP client config.

    python3 scripts/enroll.py <handle> [--url http://…]

The chat token is written to data/clients/<handle>.json (mode 600) and is never
printed: the operator copies the file, the terminal stays clean. That is the
rule this whole project runs on — a secret that shows up in a log or a
transcript has to be treated as burned.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import _env

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "adapters" / "mcp_stdio.py"


def call(url, path, body=None, token=None, method="POST"):
    req = urllib.request.Request(url + path, method=method,
                                 data=json.dumps(body).encode() if body else None)
    if body:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = json.loads(e.read() or b"{}").get("detail", e.reason)
        sys.exit(f"échec {path}: HTTP {e.code} — {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"instance injoignable sur {url} ({e.reason})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("handle", help="handle du chat, ex: cowork")
    ap.add_argument("--url", default=_env.api_url())
    ap.add_argument("--display-name")
    ap.add_argument("--client", default="claude")
    ap.add_argument("--owner-token-file", default=str(ROOT / "data" / "owner-token"))
    args = ap.parse_args()

    owner = Path(args.owner_token_file).read_text().strip()
    invite = call(args.url, "/v1/admin/invites", {"note": args.handle}, owner)
    chat = call(args.url, "/v1/register", {
        "invite_code": invite["invite_code"], "handle": args.handle,
        "display_name": args.display_name or args.handle, "client": args.client})

    config = {"mcpServers": {"hallmoot": {
        "command": "python3", "args": [str(ADAPTER)],
        "env": {"MOOT_API_URL": args.url, "MOOT_TOKEN": chat["chat_token"]}}}}

    out_dir = ROOT / "data" / "clients"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{args.handle}.json"
    out.write_text(json.dumps(config, indent=2) + "\n")
    out.chmod(0o600)

    print(f"chat @{chat['handle']} enregistré (id {chat['chat_id']})")
    print(f"config MCP écrite dans {out} (mode 600) — elle contient le jeton, "
          f"à transmettre hors bande")


if __name__ == "__main__":
    main()
