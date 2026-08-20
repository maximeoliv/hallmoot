"""The two pages a human actually sees.

Everything else in this project is an API. These two pages are the whole visible
surface of Hallmoot, shown at the one moment that matters — when someone is
deciding whether to hand a client the right to speak as them. A screen that
looks improvised at that moment is asking for a decision it has not earned.

So they carry the same identity as the site — the serif, the brass, the beams —
and they say plainly what is being granted. Two pages, because authenticating a
human and choosing an identity are different questions, and only the first one
has several possible answers.

No external asset is fetched: a consent screen that phones out to a font CDN
tells that CDN who is authorising what, and when.
"""

from __future__ import annotations

import html

# The site's tokens, verbatim, so the two never drift into cousins.
_CSS = """
:root{
  --ink:#f2ece1; --ink-dim:#9a9285; --line:#2b2721;
  --bg:#0f0e0c; --panel:#17150f; --panel-2:#1c1913;
  --brass:#d9a441; --brass-soft:#8a6a2c; --moss:#7fae8e; --rust:#c2603f;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
}
@media (prefers-color-scheme: light){
  :root{
    --ink:#1b1813; --ink-dim:#6b6255; --line:#e3ddd0;
    --bg:#faf7f0; --panel:#fffdf8; --panel-2:#f4efe4;
    --brass:#9a6c12; --brass-soft:#c9a862; --moss:#3f7a56; --rust:#a8452a;
  }
}
*{box-sizing:border-box}
body{
  margin:0; min-height:100vh; background:var(--bg); color:var(--ink);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;
  display:grid; place-items:center; padding:1.5rem;
  background-image:radial-gradient(50rem 26rem at 50% -10rem,
    color-mix(in srgb, var(--brass) 10%, transparent), transparent 70%);
}
.card{width:min(30rem,100%);background:var(--panel);border:1px solid var(--line);
  border-radius:.9rem;overflow:hidden}
.beams{height:3px;background:repeating-linear-gradient(90deg,
  var(--brass-soft) 0 2px, transparent 2px 14px);opacity:.55}
.inner{padding:1.9rem}
.mark{font-family:var(--serif);font-size:1.5rem;font-weight:600;margin:0;
  letter-spacing:-.01em}
.mark span{color:var(--brass)}
h1{font-family:var(--serif);font-size:1.45rem;font-weight:600;margin:1.4rem 0 .5rem;
  line-height:1.25;letter-spacing:-.01em}
p{margin:.5rem 0;color:var(--ink-dim);font-size:.94rem}
p.lead{color:var(--ink)}
code{font-family:var(--mono);font-size:.86em;color:var(--brass)}
label{display:block;margin:1.3rem 0 .4rem;font-size:.8rem;letter-spacing:.04em;
  text-transform:uppercase;color:var(--ink-dim)}
input,select{width:100%;padding:.75rem .85rem;border-radius:.45rem;
  border:1px solid var(--line);background:var(--panel-2);color:var(--ink);
  font-size:1rem;font-family:inherit}
input:focus,select:focus{outline:2px solid var(--brass-soft);outline-offset:1px}
button{width:100%;margin-top:1.5rem;padding:.8rem;border:0;border-radius:.45rem;
  background:var(--brass);color:#17150f;font-size:1rem;font-weight:600;
  font-family:inherit;cursor:pointer}
button:hover{filter:brightness(1.08)}
button.ghost{background:transparent;color:var(--ink);border:1px solid var(--line);
  margin-top:.6rem;font-weight:500}
.err{background:color-mix(in srgb, var(--rust) 18%, transparent);
  border-left:2px solid var(--rust);padding:.7rem .8rem;border-radius:.3rem;
  color:var(--ink);font-size:.9rem;margin:1rem 0}
.grants{list-style:none;padding:0;margin:1.2rem 0 0;border-top:1px solid var(--line)}
.grants li{padding:.65rem 0 .65rem 1.5rem;border-bottom:1px solid var(--line);
  font-size:.9rem;position:relative;color:var(--ink)}
.grants li::before{content:"";position:absolute;left:.3rem;top:1.05rem;
  width:.4rem;height:.4rem;border-radius:50%;background:var(--moss)}
.grants li.no::before{background:var(--rust)}
.grants li b{font-weight:600}
.grants li span{display:block;color:var(--ink-dim);font-size:.85rem;margin-top:.1rem}
.rule{display:flex;align-items:center;gap:.8rem;margin:1.6rem 0 .2rem;
  color:var(--ink-dim);font-size:.78rem;letter-spacing:.06em;text-transform:uppercase}
.rule::before,.rule::after{content:"";flex:1;height:1px;background:var(--line)}
.foot{margin:1.6rem 0 0;padding-top:1rem;border-top:1px solid var(--line);
  font-size:.82rem;color:var(--ink-dim)}
"""


def _shell(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=fr><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>"
        f'<div class=card><div class=beams></div><div class=inner>{body}</div></div>'
        "</body></html>"
    )


def _err(message: str) -> str:
    return f"<p class=err>{html.escape(message)}</p>" if message else ""


def sign_in_page(*, client_name: str, methods: list[dict], error: str = "",
                 notice: str = "") -> str:
    """Step one: prove you are the person who owns this instance.

    `methods` is what the operator actually configured. A method that is not
    configured is not shown — an empty field explaining it does nothing is worse
    than no field at all.
    """
    blocks: list[str] = []
    for i, m in enumerate(methods):
        if i:
            blocks.append('<div class=rule>ou</div>')
        blocks.append(m["html"])

    if not methods:
        blocks.append(
            "<p class=err>Cette instance n'a aucun moyen de connexion configuré, "
            "donc elle refuse toute autorisation. L'opérateur doit définir au "
            "moins <code>MOOT_AUTH_PASSCODE</code>.</p>")

    return _shell(
        f"Hallmoot — connexion",
        f'<p class=mark>Hall<span>moot</span></p>'
        f'<h1>Connexion à ton instance</h1>'
        f'<p class=lead><b>{html.escape(client_name)}</b> demande à se connecter. '
        f'Avant de choisir ce que tu lui confies, prouve que cette instance est '
        f'bien la tienne.</p>'
        f'{_err(error)}'
        f'{f"<p>{html.escape(notice)}</p>" if notice else ""}'
        f'{"".join(blocks)}'
        f'<p class=foot>Hallmoot n\'a qu\'un propriétaire : toi. Cette page '
        f'authentifie une personne, pas un compte parmi d\'autres.</p>')


def grant_page(*, client_name: str, options: str, fields: str, error: str = "") -> str:
    """Step two: decide which identity this client speaks as.

    The list of what it can and cannot do is not decoration. Someone clicking
    *Autoriser* is granting the right to write in their name; they are owed a
    plain statement of the shape of that right, including its limits.
    """
    return _shell(
        f"Hallmoot — autoriser {client_name}",
        f'<p class=mark>Hall<span>moot</span></p>'
        f'<h1>Autoriser « {html.escape(client_name)} »</h1>'
        f'<p class=lead>Ce client parlera au nom de l\'identité que tu choisis. '
        f'Dans Hallmoot l\'expéditeur n\'est jamais déclaré, il est déduit du '
        f'jeton — c\'est pour ça qu\'il faut le décider maintenant.</p>'
        f'{_err(error)}'
        f'<form method=post>'
        f'<label>Identité à lui confier</label>'
        f'<select name=chat_id>{options}</select>'
        f'<ul class=grants>'
        f'<li><b>Écrire et lire en ton nom</b>'
        f'<span>ses messages porteront cette identité comme expéditeur</span></li>'
        f'<li><b>Voir l\'annuaire des chats</b>'
        f'<span>pour savoir à qui il peut écrire</span></li>'
        f'<li class=no><b>Pas les autres identités</b>'
        f'<span>il ne verra rien de ce qui ne concerne pas celle-ci</span></li>'
        f'<li class=no><b>Aucun pouvoir d\'administration</b>'
        f'<span>il ne peut ni inviter, ni révoquer, ni gérer les pairs</span></li>'
        f'</ul>'
        f'{fields}'
        f'<button>Autoriser</button>'
        f'</form>'
        f'<p class=foot>Révocable à tout moment, et seule cette connexion tombe : '
        f'tes autres clients continuent de fonctionner.</p>')
