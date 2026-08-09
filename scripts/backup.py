#!/usr/bin/env python3
"""Consistent online backup of the instance database.

    python3 scripts/backup.py [--keep 14] [--db data/hallmoot.sqlite3]

Uses SQLite's own backup API rather than copying the file: with WAL enabled, a
plain `cp` can capture a database mid-transaction and produce a backup that only
fails when you need it. This runs against a live instance without stopping it.

These dumps are what the machine-level backup relies on: the live database is
excluded from it on purpose (a file copied mid-write is a file that fails the
day you need it). So the name matters — `hallmoot-<stamp>.sqlite3`, distinct
from the live `hallmoot.sqlite3` the snapshot excludes by name. Widening that
exclusion to `*.sqlite3` would silently take these with it, and nothing would
say so until a restore.

The owner token is deliberately NOT included — it lives beside the database and
is copied by whatever backs up the volume, but a database dump that carries the
instance's master credential is a dump you cannot store anywhere.
"""
from __future__ import annotations

import argparse
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def human(n: int) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(ROOT / "data" / "hallmoot.sqlite3"))
    ap.add_argument("--dest", default=str(ROOT / "data" / "backups"))
    ap.add_argument("--keep", type=int, default=14, help="how many backups to retain")
    args = ap.parse_args()

    db = Path(args.db)
    if not db.exists():
        return int(bool(sys.stderr.write(f"base introuvable: {db}\n")))

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = dest / f"hallmoot-{stamp}.sqlite3"

    src = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    dst = sqlite3.connect(out)
    try:
        src.backup(dst)
        # Collapse the WAL into the file itself: a backup must be ONE file.
        # Three files, one of them empty, is a backup someone copies halfway.
        dst.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        dst.execute("PRAGMA journal_mode=DELETE")
    finally:
        dst.close()
        src.close()
    for leftover in (Path(str(out) + "-wal"), Path(str(out) + "-shm")):
        leftover.unlink(missing_ok=True)
    out.chmod(0o600)

    # Prove the copy opens and holds the expected shape before trusting it.
    check = sqlite3.connect(f"file:{out}?mode=ro", uri=True)
    try:
        integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
        chats = check.execute("SELECT COUNT(*) FROM chats").fetchone()[0]
        messages = check.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    finally:
        check.close()
    if integrity != "ok":
        sys.stderr.write(f"SAUVEGARDE SUSPECTE: integrity_check = {integrity}\n")
        return 1

    # The code matters as much as the data. Until the repository has a remote,
    # a bundle beside the database is the only copy that survives a bad `rm`.
    bundle = dest / f"hallmoot-code-{stamp}.bundle"
    git = subprocess.run(["git", "bundle", "create", str(bundle), "--all"],
                         cwd=ROOT, capture_output=True, text=True)
    if git.returncode == 0:
        bundle.chmod(0o600)
        for stale in sorted(dest.glob("hallmoot-code-*.bundle"), reverse=True)[args.keep:]:
            stale.unlink()
        print(f"✓ {bundle.name} — {human(bundle.stat().st_size)} — dépôt complet")
    else:
        sys.stderr.write("dépôt non sauvegardé (git bundle a échoué)\n")

    kept = sorted(dest.glob("hallmoot-*.sqlite3"), reverse=True)
    for stale in kept[args.keep:]:
        stale.unlink()

    print(f"✓ {out.name} — {human(out.stat().st_size)} — {chats} chats, "
          f"{messages} messages, integrity ok")
    print(f"  {min(len(kept), args.keep)} sauvegarde(s) conservée(s) dans {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
