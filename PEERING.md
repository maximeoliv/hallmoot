# Peering — two instances that agree to talk

> Design decisions, written before the code.

## What this is

Two people each host an instance. They invite each other **explicitly**, the pairing is **mutual**
and **revocable from either side**, and their chats become addressable to one another —
`@bob@alice-place`. Nothing else: no public directory, no discovery, no open federation. You only
ever hear from peers you accepted, so the abuse surface is bounded by a list each person wrote by
hand.

## The six rules that govern the rest

**1. Pairing is mutual and explicit.** A peer cannot invite itself in: one owner mints an
invitation, the other presents it. Each instance keeps a distinct token for talking to the other,
so revoking on your side never depends on their goodwill.

**2. Nothing is exposed by default.** After pairing, **no** chat is visible to the peer. The owner
explicitly adds the chats they make addressable. A brand-new pairing therefore lets nothing
through — the safe default, and one that widens without retroactive risk.

**3. A peer vouches for its own members, and nothing more.** When an instance delivers a message
"from bob", we authenticate **the instance**, not bob: it is asserting who spoke on its side. That
is the nature of federation and it should be said, not dressed up. Concretely the sender reads
`bob@alice-place` — the suffix is proven, the prefix is the peer's claim. A dishonest peer can lie
about its members; it cannot impersonate another peer, nor anyone of ours.

**4. Session labels do not cross as identities.** Inside an instance a session is already
declarative. Across a federation boundary it becomes a display label and nothing else. It is never
used for an authorization decision.

**5. A message received from a peer is never forwarded to another peer.** Without that rule, two
pairings turn us into a relay — and a relay is what quietly turns an allow-list into an open
network.

**6. Revocation is unilateral and immediate.** Either side can cut alone. Tokens die, addresses
stop resolving, mail already received stays — it belongs to whoever received it.

## What version 1 does not do

- **No attachments between peers.** Moving arbitrary bytes from one instance to another needs its
  own work (size, latency, resumption, quotas). Messages first.
- **No groups, no transitivity.** Your peer's friend is not your peer.
- **No discovery.** There is no way to ask an instance "who do you host?": you only see the chats
  it has explicitly exposed to you.
- **No unsend or edit across the boundary.** Once it has left for the peer, a message is theirs.
  Claiming it is erasable would be a lie.

## What crosses the network

A single inbound route, `POST /v1/peer/inbox`, authenticated by the peer's token. The body carries
the claimed sender, the recipient (one of our exposed chats), a subject, a body and an optional
thread reference. Everything else — statuses, read receipts, the directory — stays local in v1:
every extra round trip is one more surface.

Delivery is **synchronous and one-shot**: if the peer is down, the sender is told immediately. A
queue retrying in silence would let someone believe a message left when it never did.

The pairing handshake follows the same discipline as the rest of the project: 256-bit tokens,
stored hashed, never shown twice, and a single-use invitation with an expiry.
