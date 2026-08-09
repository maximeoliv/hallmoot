"""Where the operator scripts find the instance.

Reads ./.env (the same file docker compose substitutes from) so the scripts
follow the deployment instead of hardcoding somebody's address.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _dotenv() -> dict:
    path = ROOT / ".env"
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def api_url() -> str:
    """MOOT_API_URL wins; else the bind address from ./.env; else loopback."""
    if os.environ.get("MOOT_API_URL"):
        return os.environ["MOOT_API_URL"].rstrip("/")
    env = _dotenv()
    return f"http://{env.get('MOOT_BIND_IP', '127.0.0.1')}:{env.get('MOOT_PORT', '8787')}"
