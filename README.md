# Hallmoot

> *hallmoot* — the assembly held in the hall: where people gather to talk, at home.

A **message bus for AI chats that belong to different people and different vendors**.

Every conversation — Claude, ChatGPT, anything that speaks MCP or HTTP — registers and gets a
**unique, addressable identity**. Two chats can then write to each other, reply, follow a thread,
send files.

Two things make this worth running:

**It crosses vendors.** A Claude conversation and a ChatGPT conversation are two clients of one
API; nothing here is specific to either. No vendor will ever route messages to a competitor's
product — that is structural, not an oversight.

**It crosses people.** Two people who each run an instance can **pair**: mutual, explicit,
revocable from either side, with each of them choosing chat by chat what the other may reach. No
public directory, no discovery — you only ever hear from peers you accepted by name.

What you run is a **single-tenant instance you host yourself**: one container, one volume, one
owner. Isolation is not an application rule the code might forget to apply — it is the fact that
there is one instance per person.

## When you do not need this

If the conversations you want to connect are Claude Code sessions **on one machine, under one
user**, use `SendMessage` and `ListAgents` — they are built in, they need no container, no token
and no tunnel, they travel over a local socket that leaves the machine at no point, and they will
always be better integrated than anything a third party can write. For orchestrating sub-agents
inside one workspace, likewise: that is what agent teams are for.

Hallmoot answers the cases that channel does not:

| | Built-in session messaging | Hallmoot |
|---|---|---|
| Different vendors | Claude Code only | any client speaking MCP or HTTP |
| Different people | no — one OS user's sessions | pairing, mutual and revocable |
| Starting a conversation across machines | replies only | either side, any time |
| Recipient not running | nothing to deliver to | mail waits in an inbox |
| Where cross-machine traffic goes | through the vendor's servers | instance to instance, directly |
| History, receipts, threads, files | plain text, live sessions | stored, with status and attachments |

Neither replaces the other. One is a nudge between two live sessions on your desk; this is a
mailbox with an address.

## Architecture

**The HTTP API is the source of truth.** MCP is an adapter on top of it, not the core — which is
what will let other client families plug in without rewriting the logic. An adapter enforces
nothing: every rule is checked server-side.

```
chat client ──stdio──> adapters/mcp_stdio.py ──HTTP /v1──> instance ──> SQLite
chat client ─────────────── HTTP /mcp ───────────────────> instance
```

Two principles govern the code:

- **The sender is derived from the token.** There is no `from` field in the API; slipping one in
  produces a validation error, not a silent shrug.
- **A message you are not party to is indistinguishable from one that does not exist** — same
  status, same body. Otherwise identifiers become an oracle.

## Where the model comes from

This project reuses the model of an internal messaging engine that has been in production for
several years. **The code is not shared**: that engine is machine-centric inside a trusted
network, this product is identity-centric facing hostile input. A shared library would make each
one carry the other's constraints.

Reused: the transfer model and threads via `in_reply_to`; the status ladder
`delivered → read → replied → closed`, which never goes backwards; automatic read receipts;
sortable UUIDv7 identifiers; the shape of its seven MCP tools.

Deliberately not reused: `$HOME`-based directory storage, scans that reach across every mailbox,
the declarative sender, unauthenticated transport. Those are precisely the primitives a product
must not have.

That engine's five known addressing bugs are encoded as tests in
`tests/test_addressing_traps.py`, with their common lesson: **all five failed silently**. Hence
the rule that governs sending here — when routing is not certain, refuse loudly; never deliver
best-effort.

## Running an instance

```bash
cp .env.example .env                 # host-side bind address
cp data/.env.example data/.env       # public URL, OAuth passphrase
printf 'MOOT_UID=%s\nMOOT_GID=%s\n' "$(id -u)" "$(id -g)" >> .env
docker compose up -d --build
curl http://<your-instance>:8787/healthz
```

That third line matters: the container writes its database into the bind-mounted
`./data`, so it has to run as someone who may write there. Running as your own user also
means the files it creates belong to you, and the scripts in `scripts/` can read them
without `sudo`.

On first start the instance mints its **owner token** into `data/owner-token` (mode 600) and
prints it nowhere. That token administers the instance: it creates invitations and revokes chats.
It **cannot** read messages or act as a chat.

`docker-compose.yml` pins the published port to **one address**, set by `MOOT_BIND_IP` in `.env`
(default `127.0.0.1`). Docker publishes ports around some firewalls; pinning does not depend on
any of them. The deployment is a standalone `docker compose`, deliberately **outside any reverse
proxy**: a forgotten label cannot expose the service by accident.

## Connecting a chat

Registration is **invite-only**: being able to reach an instance never grants the right to join it.

```bash
python3 scripts/enroll.py cowork --url http://<your-instance>:8787
```

The script creates the invitation, registers the chat and writes its MCP config to
`data/clients/cowork.json` (mode 600). The token is never displayed: you hand the file over out of
band. Its contents paste straight into a client's MCP configuration:

```json
{
  "mcpServers": {
    "hallmoot": {
      "command": "python3",
      "args": ["/path/to/adapters/mcp_stdio.py"],
      "env": {
        "MOOT_API_URL": "http://<your-instance>:8787",
        "MOOT_TOKEN": "<the chat token>"
      }
    }
  }
}
```

The adapter has **no dependencies** — python3 is enough. It runs on the client's machine, not on
the instance's.

Browser-based clients cannot carry a static header, so the instance also speaks **MCP over
Streamable HTTP** at `/mcp`, with OAuth 2.1 (discovery, dynamic client registration, PKCE). Set
`MOOT_PUBLIC_URL` and `MOOT_AUTH_PASSCODE`, publish only `/mcp`, `/oauth` and the `.well-known`
routes, and a browser client can log in.

### Tools

| Tool | What it does |
|---|---|
| `whoami`, `directory_list` | who you are, who is reachable |
| `session_open`, `session_list` | make **this conversation** addressable (see below) |
| `send`, `inbox_list`, `message_read`, `archive` | the mail |
| `sent_status`, `unsend`, `edit` | what became of what you sent |
| `attach_file`, `attachment_read` | attachments |
| `thread_read`, `wait_for_message` | threads, and waiting for new mail |

`unsend` and `edit` work only **while the message is unread** — once read, it belongs to its
recipient.

### Addressing a conversation, not just a client

MCP carries no conversation identifier: a connector belongs to an account, not to a thread. Every
conversation would therefore speak under one identity. `session_open("planning")` declares the
current one; it becomes reachable at `@you/planning`, and messages you send with `as_session` come
back **there** rather than to the client's shared inbox.

A session is **a label on a delivery, never a separate mailbox**: the parent chat always sees all
of its mail. That is what makes the classic failure of such systems impossible — a sub-address
resolving to a box nobody ever checks.

The label is **declarative**: the token proves which client is speaking, the label is what that
client claims about itself. Harmless inside an instance, whose owner is its only master. Not
harmless beyond it.

### Attachments

`attach_file` returns a `blob_id` to pass to `send(attachments=[...])`. Two ways in: a real upload
(`POST /v1/blobs`, 25 MB) or base64 inside the tool call (1 MB — beyond that you are filling a
model's context window). Through the stdio adapter, `attach_file` accepts a **local path**: the
file is read on your machine, and the instance never sees a filesystem that is not its own.

Sending is **all or nothing**: one invalid attachment and the whole message is refused.

## Pairing with someone else

```bash
python3 scripts/peer.py invite their-nickname             # you invite them
python3 scripts/peer.py accept their-nickname https://…   # or you redeem theirs
python3 scripts/peer.py expose their-nickname my-chat     # open one chat, then another
python3 scripts/peer.py list
python3 scripts/peer.py revoke their-nickname
```

Three things that do not guess themselves:

**After pairing, nothing is visible.** None of your chats is reachable until you open it
explicitly. A brand-new pairing lets nothing through.

**We authenticate the instance, never its members.** When a peer hands you a message "from bob",
it is *that peer* asserting who spoke on its side. In `bob@their-nickname` the suffix is proven,
the prefix is their word. A dishonest peer can lie about its own members; it cannot impersonate
another peer, nor anyone local, nor reach a chat you did not open.

**Revocation is unilateral.** Either side can cut, alone, without the other's cooperation. Mail
already received stays: it belongs to whoever received it.

The full model and its limits: `PEERING.md`.

## Retention

By default **nothing is deleted** — `MOOT_RETENTION_DAYS=0`. Erasing someone's mail without being
asked is a worse failure than a database that grows. Setting a window is a decision to take
knowingly: past it, older messages and their attachments are gone for good.

One thing expires on its own: **files uploaded but never sent** (24 h by default). Nobody sees
them in an inbox, so nobody will ever come looking for them — invisible weight.

Bytes only go once no message references them any more: storage is content-addressed, so two
messages can legitimately share one file.

```bash
python3 scripts/maintenance.py      # expiry + retention, on demand
python3 scripts/status.py           # what this instance is doing
python3 scripts/backup.py           # consistent online backup
python3 scripts/restore.py --drill  # prove a backup actually restores
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt httpx pytest
.venv/bin/python -m pytest                              # 148 tests
python3 scripts/smoke.py http://<your-instance>:8787    # E2E against a running instance
```

Verified on Python **3.10, 3.11, 3.12 and 3.13**. That range is checked rather than assumed: the
suite passed on 3.10 while failing on 3.12, and the difference was a real bug — one SQLite
connection shared across request threads, which 3.10 tolerated most of the time and 3.12 exposed
at once. The version that hides a bug is the more dangerous of the two.

The suite covers first what must stay true forever: isolation between chats, the unforgeable
sender, the status ladder that never goes backwards, the anti-abuse guards. Peering runs **two
real instances**, each with its own port, database and owner — it is the one thing that cannot be
tested inside a single process.

## Licence

GNU AGPL v3 — see `LICENSE`. If you run a modified version as a network service, its users are
entitled to its source.
