#!/usr/bin/env python3
"""Nightly housekeeping: expire credentials, apply retention, drop dead weight.

    python3 scripts/maintenance.py

Runs after the backup on purpose: we keep a copy of what we are about to delete,
never the other way round.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import _env

ROOT = Path(__file__).resolve().parent.parent


def call(path: str, token: str) -> dict:
    req = urllib.request.Request(_env.api_url() + path, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def main() -> int:
    token_file = ROOT / "data" / "owner-token"
    if not token_file.exists():
        return int(bool(sys.stderr.write("data/owner-token introuvable\n")))
    token = token_file.read_text().strip()
    try:
        gc = call("/v1/admin/gc", token)["purged"]
        retention = call("/v1/admin/retention", token)
    except urllib.error.HTTPError as e:
        # The server answered — saying "unreachable" here sends whoever reads
        # this log looking at the network instead of at the deployed version.
        return int(bool(sys.stderr.write(
            f"l'instance a refusé: HTTP {e.code} sur {e.url} "
            f"(version déployée trop ancienne ?)\n")))
    except urllib.error.URLError as e:
        return int(bool(sys.stderr.write(
            f"instance injoignable sur {_env.api_url()} ({e.reason})\n")))

    dropped = retention["dropped"]
    moved = {k: v for k, v in {**gc, **dropped}.items() if v}
    print("ménage :", ", ".join(f"{v} {k}" for k, v in moved.items()) if moved
          else "rien à faire")
    if retention["window_days"] == 0 and dropped["messages"] == 0:
        print("  rétention désactivée (MOOT_RETENTION_DAYS=0) — aucun message supprimé")
    return 0


if __name__ == "__main__":
    sys.exit(main())
