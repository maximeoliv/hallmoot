#!/usr/bin/env python3
"""Does a session's address survive the session being restarted?

This is the question that decides whether Hallmoot can carry a fleet's mail.
Claude Code sessions restart constantly — a reboot, a crash, a launcher firing at
boot. If every restart demanded a human to re-authenticate, a fleet of dozens of
sessions would be unmanageable, and the answer would be no.

So this does not argue. It runs the thing:

  1. enrol a chat, which writes a token file and nothing else;
  2. start an adapter process, open the session label `alpha`, stop the process
     the way a killed session stops — SIGKILL, no cleanup, no goodbye;
  3. from a second chat, send a message to @probe/alpha while nothing is running;
  4. start a *new* adapter process against the same token file, and see whether
     the message is there.

Step 4 is the whole point. A new process, no human in the loop, no interactive
step: exactly what a Claude Code session does when it comes back up.

Usage:  python3 scripts/restart_drill.py [--keep]
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "adapters" / "mcp_stdio.py"
API = os.environ.get("MOOT_API_URL", "http://127.0.0.1:8787")


# --------------------------------------------------------------------------
# talking to the instance as its owner


def _owner_token() -> str:
    return (ROOT / "data" / "owner-token").read_text().strip()


def _api(method: str, path: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            **({"Content-Type": "application/json"} if data else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


def _enrol(handle: str, owner: str) -> str:
    """Mint an invitation and redeem it, returning the chat's token."""
    inv = _api("POST", "/v1/admin/invites", owner, {"note": handle})
    reg = _api("POST", "/v1/register", owner, {
        "invite_code": inv["invite_code"], "handle": handle,
        "display_name": handle, "client": "drill"})
    return reg["chat_token"]


# --------------------------------------------------------------------------
# driving an adapter process the way a client does


class Adapter:
    """One adapter process, spoken to over stdio in JSON-RPC."""

    def __init__(self, token: str, label: str):
        env = {
            **os.environ,
            "MOOT_API_URL": API,
            "MOOT_TOKEN": token,
            "MOOT_APP_NAME": label,
        }
        self.p = subprocess.Popen(
            [sys.executable, str(ADAPTER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            text=True,
            bufsize=1,
        )
        self._id = 0
        self._rpc("initialize", {"protocolVersion": "2024-11-05",
                                 "capabilities": {}, "clientInfo": {"name": label}})

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError(f"the adapter died before answering {method}")
        return json.loads(line)

    def call(self, tool: str, args: dict | None = None) -> dict:
        r = self._rpc("tools/call", {"name": tool, "arguments": args or {}})
        content = r.get("result", {}).get("content", [])
        if not content:
            return r.get("result", {})
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}

    def kill(self) -> None:
        """Stop the way a killed session stops: no cleanup, no goodbye."""
        self.p.send_signal(signal.SIGKILL)
        self.p.wait(timeout=10)


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the probe chats behind for inspection")
    args = ap.parse_args()

    stamp = str(int(time.time()))[-6:]
    probe, sender = f"restart-probe-{stamp}", f"restart-peer-{stamp}"
    owner = _owner_token()
    failures: list[str] = []

    def check(ok: bool, label: str, detail: str = "") -> None:
        print(f"  {'✓' if ok else '✗'} {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(label)

    print(f"→ enrôlement de @{probe} et @{sender}")
    probe_token = _enrol(probe, owner)
    sender_token = _enrol(sender, owner)

    print("→ session 1 : ouverture de l'étiquette 'alpha'")
    a1 = Adapter(probe_token, "session-1")
    who = a1.call("whoami")
    check(who.get("handle") == probe, "l'adaptateur s'authentifie par son fichier de jeton",
          f"@{who.get('handle')}")
    a1.call("session_open", {"label": "alpha"})
    sessions = a1.call("session_list")
    labels = [s.get("label") for s in sessions.get("sessions", [])]
    check("alpha" in labels, "la session est déclarée", ", ".join(labels) or "aucune")

    print("→ la session est tuée (SIGKILL, sans préavis)")
    a1.kill()
    time.sleep(1)

    print("→ un message est envoyé pendant que rien ne tourne")
    _api("POST", "/v1/messages", sender_token, {
        "to": f"@{probe}/alpha",
        "subject": "survit-elle ?",
        "body": "Envoyé alors que la session était morte.",
    })

    print("→ session 2 : nouveau processus, même fichier de jeton, aucune intervention humaine")
    a2 = Adapter(probe_token, "session-2")
    who2 = a2.call("whoami")
    check(who2.get("handle") == probe, "la nouvelle session a repris la même adresse",
          f"@{who2.get('handle')}")

    sessions2 = a2.call("session_list")
    labels2 = [s.get("label") for s in sessions2.get("sessions", [])]
    check("alpha" in labels2, "l'étiquette de session a survécu au redémarrage",
          ", ".join(labels2) or "aucune")

    inbox = a2.call("inbox_list", {"session": "alpha"})
    msgs = inbox.get("messages", [])
    got = [m for m in msgs if m.get("subject") == "survit-elle ?"]
    check(bool(got), "le message envoyé pendant l'arrêt a été retrouvé",
          f"{len(msgs)} message(s) dans la session")

    if got:
        body = a2.call("message_read", {"id": got[0]["id"]})
        check("session était morte" in json.dumps(body, ensure_ascii=False),
              "le contenu est intact")

    a2.kill()

    if not args.keep:
        print("→ nettoyage des chats de test")
        for h in (probe, sender):
            try:
                chats = _api("GET", "/v1/admin/chats", owner).get("chats", [])
                for c in chats:
                    if c.get("handle") == h:
                        _api("DELETE", f"/v1/admin/chats/{c['id']}", owner)
            except urllib.error.HTTPError as e:  # pragma: no cover - diagnostic only
                print(f"  (nettoyage de @{h} impossible : {e})")

    print()
    if failures:
        print(f"VERDICT : NON — {len(failures)} point(s) en échec : {', '.join(failures)}")
        return 1
    print("VERDICT : OUI — l'adresse d'une session survit à son redémarrage,")
    print("          et un message envoyé pendant l'arrêt attend au retour.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
