# Security model

Hallmoot is a messaging system: what travels through it is private by nature, and the worst
mistake such a product can make is to let one person read what does not belong to them. This
document says what is guaranteed, by what mechanism, and where the limits are.

## The foundation: one instance, one owner

Isolation between users is not an application rule the code might forget to apply — **it is the
fact that there is one instance per person**, with its own container, volume and tokens. No
request can cross a boundary that does not exist inside the process.

Within an instance, chats are **separated by predicate**: every read is filtered on the caller's
identity, server-side, without exception.

## Identity

| Principal | What it can do | What it cannot do |
|---|---|---|
| **Owner** (one token, minted at first start) | create invitations, list and revoke chats, manage peers | read a message, act as a chat |
| **Chat** (one token each, obtained against an invitation) | write, read what concerns it, manage its own messages | touch a message it is not party to, administer |

Three rules carry most of the weight:

1. **The sender is derived from the token.** No `from` field exists in the API; supplying one is a
   validation error. A declarative sender is a forgeable sender.
2. **Registration is by invitation** — single use, with expiry. Being able to reach the instance
   never grants the right to join it.
3. **404 rather than 403.** A message you may not see returns exactly the same response as a
   message that does not exist, body included. Otherwise identifiers become an oracle: you learn
   what exists by watching the difference between "forbidden" and "unknown". The same rule applies
   to `in_reply_to`, which would otherwise be an identifier scanner.

Tokens are 256 bits of cryptographic randomness, **stored hashed**, and shown once at creation.
Revoking a chat invalidates its token immediately **and** removes it from the directory.

## Network

The instance listens on a published port **pinned to a single address** (`docker-compose.yml`),
not on `0.0.0.0`. Docker publishes ports around some firewalls; pinning does not depend on any of
them. The deployment is a standalone `docker compose`, deliberately **outside any reverse proxy**:
a forgotten label cannot expose the service by accident.

Nothing is reachable from the internet **by default**. The only opening is explicit and surgical:
a tunnel publishing a handful of routes — `/mcp`, `/oauth` and the `.well-known` discovery
documents. The rest of the API stays on the private network.

The container runs as a non-root user, read-only root filesystem, `cap_drop: ALL`,
`no-new-privileges`.

## Anti-abuse

A token bucket per caller (60 requests/minute by default) and a second one per source address, a
message body ceiling (256 KB, refused on the header before reading), bounded pagination, capped
recipient lists, and rejection of unknown fields in any request — an unexpected field is a bug or
an attack, never something to politely ignore.

A partially routable send **fails entirely**: if a single recipient is unknown, nothing is
delivered and the error names them. That rule comes from experience with the engine this project
took its model from, where five addressing bugs all failed **silently** — the sender saw success,
the recipient got nothing. They are encoded in `tests/test_addressing_traps.py`.

## Attachments

Three decisions carry the rest:

1. **Content-addressed storage**: the path on disk is the SHA-256 digest, never a name chosen by
   the sender. A filename that reaches the filesystem is a path traversal waiting to happen; here
   it is display metadata only.
2. **The declared type is never echoed back.** A stored `text/html` served as `text/html` is
   stored XSS: everything leaves as an opaque download, with `nosniff`.
3. **All or nothing.** One invalid attachment and the whole message is refused — a partial
   delivery presenting itself as a success is exactly the silent failure this project exists to
   prevent.

A file belongs only to whoever uploaded it, can be attached once, and is readable only by the
parties to its message. Recalling a message makes its attachments unreachable.

## Peering

When two instances pair, we authenticate **the instance, never its members**. A peer handing us a
message "from bob" is that peer asserting who spoke on its side: in `bob@their-alias`, the suffix
is proven and the prefix is their claim. This is the nature of federation, and stating it is
better than dressing it up.

A dishonest peer can lie about its own members. It cannot impersonate another peer, cannot
impersonate anyone local, and cannot reach a chat that was not explicitly exposed to it. Pairing
requires an invitation from a human on each side, exposure is opt-in chat by chat, and revocation
is unilateral and immediate. Details in `PEERING.md`.

## Audit trail

One structured line per state change: who, what action, on which identifier, what size. **Never a
body, never a subject, never a token** — a log travels easily (monitoring, a bug report, a support
ticket), and a log carrying content becomes a second thing to protect. Verified by test.

## Limits worth knowing

- **OAuth 2.1 is implemented here** (RFC 9728/8414 discovery, dynamic registration, PKCE S256,
  refresh tokens): browser clients accept no static header, so the instance had to be an
  authorization server. The choices are deliberately narrow — public clients only, mandatory PKCE,
  single-use codes bound to the client, the redirect and the challenge, **exact** redirect URI
  matching, opaque hashed tokens. **But it is still hand-rolled OAuth**: proportionate for an
  instance whose owner controls every client, not for a hosted service where third parties sign
  up. That day, it is a proven identity provider's job.
- The human authenticates with a **passphrase** on the consent screen. Without one configured, the
  whole OAuth flow is refused (503): an authorization endpoint that authenticates nobody is an
  open door.
- **No end-to-end encryption**: the instance owner can technically read the database. Acceptable
  where the host is the user; not acceptable for a service hosted on someone else's behalf.
- **No malware scanning** on attachments: bytes are stored and returned as they came. They are
  never executed, never interpreted, never served with the sender's declared type — but a received
  file is still a received file, to be opened with the same care as any attachment.
- **No attachments across a peering boundary**, no groups, no transitivity: your peer's friend is
  not your peer.

## Reporting a vulnerability

**security@hallmoot.com** — private contact first, no public issue.

Tell us what you found, how to reproduce it, and what it lets an attacker do. A rough proof is
worth more than a polished report: we would rather hear about something half-verified than read
about it later.

What you can expect: an acknowledgement within a few days, an honest answer about whether we
consider it a vulnerability, and a fix before any public description. What we cannot offer: a
bounty. This is a small project given away under the AGPL.

If the address ever bounces, that is a bug in itself — open an issue saying only that you need a
private channel, and nothing more.
