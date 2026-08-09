#!/usr/bin/env python3
"""What is my instance doing? — the operator's one-screen answer.

    python3 scripts/status.py

Whoever runs their own instance has no dashboard and nobody to ask. This prints
the handful of numbers that actually tell you whether things are healthy, plus
the two that go wrong quietly: mail nobody has read, and backups nobody made.
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import _env

ROOT = Path(__file__).resolve().parent.parent


def human(n: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024


def age(iso: str | None) -> str:
    if not iso:
        return "jamais"
    try:
        then = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return iso
    hours = (datetime.now(timezone.utc) - then).total_seconds() / 3600
    if hours < 1:
        return f"il y a {int(hours * 60)} min"
    if hours < 48:
        return f"il y a {int(hours)} h"
    return f"il y a {int(hours / 24)} j"


def main() -> int:
    owner = (ROOT / "data" / "owner-token")
    if not owner.exists():
        return int(bool(sys.stderr.write("data/owner-token introuvable\n")))
    req = urllib.request.Request(
        _env.api_url() + "/v1/admin/status",
        headers={"Authorization": f"Bearer {owner.read_text().strip()}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            s = json.loads(r.read())
    except urllib.error.URLError as e:
        return int(bool(sys.stderr.write(
            f"instance injoignable sur {_env.api_url()} ({e.reason})\n")))

    i, t, c, st, lim = (s["identities"], s["traffic"], s["credentials"],
                        s["storage"], s["limits"])
    print(f"Hallmoot {s['version']} — {_env.api_url()}")
    revoked = f", {i['revoked']} révoqués" if i["revoked"] else ""
    print(f"  identités   {i['chats']} chats actifs, {i['sessions']} conversations{revoked}")
    statuses = ", ".join(f"{v} {k}" for k, v in sorted(t["deliveries_by_status"].items()))
    print(f"  trafic      {t['messages']} messages ({statuses or 'aucune remise'})"
          f" · plus ancien {age(t['oldest_message'])}")
    if t["unread"]:
        print(f"              ⚠ {t['unread']} remise(s) jamais lue(s)")
    print(f"  accès       {c['oauth_clients']} connecteur(s) OAuth, "
          f"{c['live_access_tokens']} jeton(s) actif(s) · "
          f"OAuth {'activé' if c['oauth_enabled'] else 'désactivé'}"
          f"{' · public: ' + c['public_url'] if c['public_url'] else ' · privé'}")
    print(f"  stockage    base {human(st['database_bytes'])} · "
          f"{st['backups']} sauvegarde(s)")
    if st["latest_backup"]:
        print(f"              dernière : {st['latest_backup']}")
    else:
        print("              ⚠ aucune sauvegarde")
    print(f"  plafonds    {lim['per_token_per_min']}/min par jeton, "
          f"{lim['per_ip_per_min']}/min par adresse, "
          f"corps ≤ {human(lim['max_body_bytes'])}")

    # The timer is what makes backups happen; its absence is invisible otherwise.
    timer = subprocess.run(["systemctl", "is-active", "hallmoot-backup.timer"],
                           capture_output=True, text=True).stdout.strip()
    print(f"  sauvegarde  timer systemd : {timer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
