#!/usr/bin/env python3
"""Watch an inbox and log what arrives — the operator's end of a live test.

    python3 scripts/watch.py <handle> [--url ...] [--log data/watch.log]

Long-polls /v1/events, then reads each incoming message (which marks it read,
so the sender watches delivered → read happen for real). Appends one readable
block per message to the log; the terminal stays free.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import _env

ROOT = Path(__file__).resolve().parent.parent


def call(url, path, token, method="GET", body=None):
    req = urllib.request.Request(url + path, method=method,
                                 data=json.dumps(body).encode() if body else None)
    if body:
        req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("handle")
    ap.add_argument("--url", default=_env.api_url())
    ap.add_argument("--log", default=str(ROOT / "data" / "watch.log"))
    args = ap.parse_args()

    cfg = json.loads((ROOT / "data" / "clients" / f"{args.handle}.json").read_text())
    token = cfg["mcpServers"]["hallmoot"]["env"]["MOOT_TOKEN"]
    log = Path(args.log)
    log.parent.mkdir(parents=True, exist_ok=True)

    def write(text):
        with log.open("a") as f:
            f.write(text + "\n")
        print(text, flush=True)

    write(f"── écoute de @{args.handle} démarrée à "
          f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} UTC ──")

    cursor = 0
    while True:
        try:
            events = call(args.url, f"/v1/events?since={cursor}&timeout=25", token)
        except urllib.error.URLError as e:
            write(f"[transport] {e.reason} — nouvelle tentative dans 5 s")
            time.sleep(5)
            continue
        cursor = events["cursor"]
        for ev in events["events"]:
            if ev["type"] != "message.received":
                write(f"[{ev['type']}] {ev.get('message_id', '')}")
                continue
            m = call(args.url, f"/v1/messages/{ev['message_id']}", token)
            write(f"\n┌─ de @{m['from']} — {m['subject']}\n│ {m['body']}\n"
                  f"└─ id {m['id']} · thread {m['thread_id']}")


if __name__ == "__main__":
    sys.exit(main())
