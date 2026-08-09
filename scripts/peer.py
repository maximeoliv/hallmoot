#!/usr/bin/env python3
"""Pair with someone else's instance, from the command line.

    python3 scripts/peer.py invite <alias>          # you invite them
    python3 scripts/peer.py accept <alias> <url>    # you redeem their invitation
    python3 scripts/peer.py list
    python3 scripts/peer.py expose <alias> <chat>
    python3 scripts/peer.py hide <alias> <chat>
    python3 scripts/peer.py revoke <alias>

Pairing is a decision between two people, so it lives here rather than in the
chat tools: no chat can invite anyone, only the owner of an instance can.

Invitation codes are written to a file (mode 600), never printed. They are
credentials: whoever holds one can pair with you.
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


def call(path: str, body=None, method="GET"):
    token = (ROOT / "data" / "owner-token").read_text().strip()
    req = urllib.request.Request(_env.api_url() + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read() or b"{}").get("detail", "")
        except Exception:
            pass
        sys.exit(f"refusé (HTTP {e.code}) : {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"instance injoignable sur {_env.api_url()} ({e.reason})")


def cmd_invite(args) -> None:
    res = call("/v1/admin/peers/invite", {"alias": args.alias}, "POST")
    out_dir = ROOT / "data" / "peer-invites"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{res['alias']}.txt"
    out.write_text(
        f"""INVITATION D'APPAIRAGE HALLMOOT
================================

À transmettre à la personne que tu invites, hors bande (pas dans un salon de
discussion : un prévisualiseur de liens ou un historique la garderait).

  URL de ton instance : {res['base_url'] or '<ton URL publique>'}
  Code d'invitation   : {res['invite_code']}

De son côté, une seule commande :

  python3 scripts/peer.py accept <le-surnom-qu-elle-te-donne> {res['base_url'] or '<ton URL>'}

Usage unique, expire sous 24 h. Une fois appairés, AUCUN chat n'est visible :
chacun ouvre les siens avec `peer.py expose`.
""")
    out.chmod(0o600)
    print(f"invitation pour @{res['alias']} écrite dans {out} (mode 600)")
    print("le code n'est pas affiché ici : c'est un credential, il ne doit pas traîner"
          " dans un terminal")


def cmd_accept(args) -> None:
    invite = args.code
    if invite is None:
        path = Path(args.code_file) if args.code_file else None
        if path is None or not path.is_file():
            sys.exit("donne --code ou --code-file (le fichier reçu de ton pair)")
        invite = next((l.split(":", 1)[1].strip() for l in path.read_text().splitlines()
                       if l.strip().startswith("Code d'invitation")), "").strip()
        if not invite:
            sys.exit("aucun code trouvé dans le fichier")
    res = call("/v1/admin/peers/accept",
               {"alias": args.alias, "base_url": args.url, "invite_code": invite}, "POST")
    print(f"appairé avec @{res['alias']} ({res['state']})")
    print("aucun de tes chats n'est visible pour l'instant :")
    print(f"  python3 scripts/peer.py expose {res['alias']} <ton-chat>")


def cmd_list(args) -> None:
    res = call("/v1/admin/peers")
    for inv in res.get("pending_invites", []):
        print(f"  @{inv['alias']:<20} invité   en attente de sa réponse "
              f"(expire {inv['expires_at']})")
    if not res["count"]:
        if not res.get("pending_invites"):
            print("aucun pair")
        return
    for p in res["peers"]:
        state = p["state"] if p["state"] != "active" else "actif"
        exposed = ", ".join("@" + h for h in p["exposed_chats"]) or "aucun chat exposé"
        seen = f" · vu {p['last_seen']}" if p["last_seen"] else ""
        print(f"  @{p['alias']:<20} {state:<8} {exposed}{seen}")
        print(f"    {p['base_url']}")


def cmd_expose(args) -> None:
    call(f"/v1/admin/peers/{args.alias}/expose", {"chat": args.chat}, "POST")
    print(f"@{args.chat} est maintenant joignable par @{args.alias}")


def cmd_hide(args) -> None:
    call(f"/v1/admin/peers/{args.alias}/expose/{args.chat}", method="DELETE")
    print(f"@{args.chat} n'est plus joignable par @{args.alias}")


def cmd_revoke(args) -> None:
    call(f"/v1/admin/peers/{args.alias}", method="DELETE")
    print(f"@{args.alias} révoqué — ses jetons sont morts, ses adresses ne résolvent plus")
    print("le courrier déjà reçu reste : il appartient à qui l'a reçu")


def main() -> int:
    ap = argparse.ArgumentParser(description="appairage entre instances Hallmoot")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("invite", help="émettre une invitation pour quelqu'un")
    p.add_argument("alias", help="surnom local que TU donnes à ce pair")
    p.set_defaults(func=cmd_invite)

    p = sub.add_parser("accept", help="utiliser l'invitation reçue de quelqu'un")
    p.add_argument("alias", help="surnom local que TU donnes à ce pair")
    p.add_argument("url", help="URL publique de son instance")
    p.add_argument("--code", help="code d'invitation")
    p.add_argument("--code-file", help="fichier d'invitation qu'il t'a transmis")
    p.set_defaults(func=cmd_accept)

    sub.add_parser("list", help="tes pairs et ce qui leur est ouvert").set_defaults(func=cmd_list)

    p = sub.add_parser("expose", help="ouvrir un de tes chats à un pair")
    p.add_argument("alias")
    p.add_argument("chat")
    p.set_defaults(func=cmd_expose)

    p = sub.add_parser("hide", help="refermer un chat")
    p.add_argument("alias")
    p.add_argument("chat")
    p.set_defaults(func=cmd_hide)

    p = sub.add_parser("revoke", help="couper un pair")
    p.add_argument("alias")
    p.set_defaults(func=cmd_revoke)

    args = ap.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
