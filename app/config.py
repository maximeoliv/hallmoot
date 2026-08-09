"""Instance configuration — everything comes from the environment.

Single-tenant by design: one instance, one owner. See PHASE1-PLAN.md §4.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

# The product name lives HERE and in the MOOT_ env prefix, nowhere else —
# not in the schema, not in the API paths. Renaming stays a one-line change.
APP_NAME = os.environ.get("MOOT_APP_NAME", "hallmoot")

DB_PATH = Path(os.environ.get("MOOT_DB_PATH", "/data/hallmoot.sqlite3"))

# Limits. Enforced from day one even though Phase 1 is single-tenant: this is
# the code that will eventually face the public internet.
MAX_BODY_BYTES = int(os.environ.get("MOOT_MAX_BODY_BYTES", 256 * 1024))
MAX_SUBJECT_LEN = 200
RATE_LIMIT_PER_MIN = int(os.environ.get("MOOT_RATE_LIMIT_PER_MIN", 60))
# Second ceiling, per source address: the per-token bucket does nothing against
# a flood of unauthenticated requests once the instance faces the internet.
RATE_LIMIT_PER_IP_PER_MIN = int(os.environ.get("MOOT_RATE_LIMIT_PER_IP_PER_MIN", 240))
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50
INVITE_TTL_SECONDS = int(os.environ.get("MOOT_INVITE_TTL_SECONDS", 24 * 3600))
EVENTS_POLL_TIMEOUT = float(os.environ.get("MOOT_EVENTS_POLL_TIMEOUT", 25.0))

# OAuth. PUBLIC_URL is the origin browser-based clients see; it must match the
# issuer they discover, or the flow breaks in ways that are hard to read.
PUBLIC_URL = os.environ.get("MOOT_PUBLIC_URL", "").rstrip("/")
# Passphrase typed once on the consent screen. Without it, no OAuth flow is
# possible at all — an authorization endpoint that authenticates nobody is a
# public door.
AUTH_PASSCODE = os.environ.get("MOOT_AUTH_PASSCODE", "").strip()
ACCESS_TOKEN_TTL = int(os.environ.get("MOOT_ACCESS_TOKEN_TTL", 3600))
AUTH_CODE_TTL = 120

# Attachments. Deliberately modest: this is a message bus, not a file host, and
# every megabyte allowed is a megabyte someone will send you.
MAX_ATTACHMENT_BYTES = int(os.environ.get("MOOT_MAX_ATTACHMENT_BYTES", 25 * 1024 * 1024))
MAX_ATTACHMENTS_PER_MESSAGE = int(os.environ.get("MOOT_MAX_ATTACHMENTS", 10))
BLOB_DIR = DB_PATH.parent / "blobs"
# Base64 through a tool call travels inside a model's context window. Small on
# purpose: anything bigger belongs in a real upload.
MAX_INLINE_ATTACHMENT_BYTES = int(os.environ.get("MOOT_MAX_INLINE_ATTACHMENT_BYTES", 1024 * 1024))

# Retention. 0 = keep everything, and that is the default on purpose: silently
# deleting someone's messages is a worse failure than a database that grows.
# Setting this is a decision the owner makes knowingly.
RETENTION_DAYS = int(os.environ.get("MOOT_RETENTION_DAYS", 0))
# Bytes uploaded but never sent are invisible weight: nobody sees them in an
# inbox, and nobody will ever come looking. They expire on their own.
ORPHAN_BLOB_HOURS = int(os.environ.get("MOOT_ORPHAN_BLOB_HOURS", 24))

# Peering. A peer is a whole other instance, so it gets its own ceiling: one
# misbehaving partner must not be able to drown us.
PEER_INVITE_TTL_SECONDS = int(os.environ.get("MOOT_PEER_INVITE_TTL", 24 * 3600))
PEER_RATE_LIMIT_PER_MIN = int(os.environ.get("MOOT_PEER_RATE_LIMIT_PER_MIN", 120))
PEER_TIMEOUT_SECONDS = float(os.environ.get("MOOT_PEER_TIMEOUT", 15.0))
# Peers must be reached over TLS: a pairing token travelling in clear over a
# network you do not own is a pairing token someone else has. The exception is
# for rehearsals on a machine you control, where two instances talk over a local
# bridge — say so explicitly rather than quietly weakening the rule.
ALLOW_INSECURE_PEERS = os.environ.get("MOOT_ALLOW_INSECURE_PEERS", "").strip() == "1"


def owner_token() -> str:
    """Owner token: from the env, else minted once and written next to the DB.

    Never logged, never returned by any endpoint. On first boot we print the
    *path*, not the value — secrets do not belong in logs or transcripts.
    """
    env = os.environ.get("MOOT_OWNER_TOKEN", "").strip()
    if env:
        return env
    path = DB_PATH.parent / "owner-token"
    if path.exists():
        return path.read_text().strip()
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n")
    path.chmod(0o600)
    print(f"[{APP_NAME}] owner token minted → {path} (mode 600)", flush=True)
    return token
