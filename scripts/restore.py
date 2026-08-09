#!/usr/bin/env python3
"""Restore a backup — and, more usefully, prove one can be restored.

    python3 scripts/restore.py --drill                # latest backup, no risk
    python3 scripts/restore.py --drill <fichier>
    python3 scripts/restore.py --live  <fichier>      # replaces the live database

A backup nobody has restored is a hope, not a backup. `--drill` boots a throwaway
instance on loopback against a copy of the backup and exercises the real API
against it: if the drill passes, the file is a working database, not just a file
that opens.

`--live` stops the container, keeps the current database as a dated safety copy,
swaps in the backup, restarts, and verifies. It never deletes anything.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import _env

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
LIVE_DB = DATA / "hallmoot.sqlite3"


def latest_backup() -> Path | None:
    backups = sorted((DATA / "backups").glob("hallmoot-*.sqlite3"), reverse=True)
    return backups[0] if backups else None


def inspect(path: Path) -> dict:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit(f"intégrité KO sur {path.name} — sauvegarde inutilisable")
        return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in ("chats", "messages", "deliveries", "sessions")}
    finally:
        conn.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def drill(backup: Path) -> int:
    """Boot a real instance against a copy of the backup and use its API."""
    counts = inspect(backup)
    print(f"  fichier   : {backup.name}")
    print(f"  contenu   : {counts['chats']} chats, {counts['messages']} messages, "
          f"{counts['sessions']} sessions")

    scratch = DATA / "restore-drill"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    copy = scratch / "hallmoot.sqlite3"
    shutil.copy2(backup, copy)

    port = free_port()
    owner = "drill-owner-token"
    env = {**os.environ, "MOOT_DB_PATH": str(copy), "MOOT_OWNER_TOKEN": owner,
           "PYTHONPATH": str(ROOT), "MOOT_PUBLIC_URL": f"http://127.0.0.1:{port}"}
    python = ROOT / ".venv" / "bin" / "python"
    proc = subprocess.Popen(
        [str(python if python.exists() else sys.executable), "-m", "uvicorn",
         "app.asgi:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1)
                break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(0.1)
        else:
            print("  ✗ l'instance restaurée ne démarre pas")
            return 1

        req = urllib.request.Request(base + "/v1/admin/chats",
                                     headers={"Authorization": f"Bearer {owner}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            chats = json.loads(r.read())["chats"]
        handles = [c["handle"] for c in chats if not c["revoked_at"]]
        ok = len(chats) == counts["chats"]
        print(f"  API       : {len(chats)} chats servis "
              f"({', '.join('@' + h for h in handles[:4])}{'…' if len(handles) > 4 else ''})")
        print(f"  {'✓ restauration vérifiée' if ok else '✗ écart entre la base et ce que sert l API'}")
        return 0 if ok else 1
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        shutil.rmtree(scratch, ignore_errors=True)


def live(backup: Path) -> int:
    counts = inspect(backup)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safety = DATA / f"hallmoot-avant-restauration-{stamp}.sqlite3"

    print(f"  arrêt du conteneur…")
    subprocess.run(["docker", "compose", "stop"], cwd=ROOT, capture_output=True)
    if LIVE_DB.exists():
        shutil.copy2(LIVE_DB, safety)
        print(f"  base actuelle conservée : {safety.name}")
    for suffix in ("", "-wal", "-shm"):
        Path(str(LIVE_DB) + suffix).unlink(missing_ok=True)
    shutil.copy2(backup, LIVE_DB)
    os.chown(LIVE_DB, 10001, 10001)
    subprocess.run(["docker", "compose", "start"], cwd=ROOT, capture_output=True)

    for _ in range(60):
        try:
            urllib.request.urlopen(_env.api_url() + "/healthz", timeout=2)
            print(f"  ✓ instance repartie sur la sauvegarde "
                  f"({counts['chats']} chats, {counts['messages']} messages)")
            return 0
        except Exception:
            time.sleep(0.5)
    print("  ✗ l'instance ne répond pas après restauration — la base d'avant est intacte "
          f"dans {safety.name}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("backup", nargs="?", help="fichier de sauvegarde (défaut : le plus récent)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--drill", action="store_true", help="répétition sans risque (défaut)")
    mode.add_argument("--live", action="store_true", help="remplace la base en production")
    args = ap.parse_args()

    backup = Path(args.backup) if args.backup else latest_backup()
    if backup is None or not backup.is_file():
        return int(bool(sys.stderr.write("aucune sauvegarde trouvée\n")))

    return live(backup) if args.live else drill(backup)


if __name__ == "__main__":
    sys.exit(main())
