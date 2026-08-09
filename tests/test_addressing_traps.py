"""The five addressing traps the original engine fell into.

They were reported by its maintainer after several years in production, and the
common thread matters more than the individual cases: **all five failed
silently** — the sender saw a success, the recipient got nothing, nobody was
told.

Hence the rule these tests defend: *no delivery may fail without noise*. When
routing is not certain, refuse loudly; never do a best-effort delivery.
"""


def _send(client, sender, to, **kw):
    return client.post("/v1/messages", headers=sender["headers"],
                       json={"to": to, "subject": kw.pop("subject", "s"),
                             "body": kw.pop("body", "b"), **kw})


# Trap 2 — an alias that resolves to a box nobody ever reads.
# The engine accepted `host:session` addresses that landed in a directory no
# scanner looked at. Here every recipient must resolve to a registered chat, and
# the delivery row is keyed on the very same chat id the inbox reads from.

def test_every_address_form_lands_in_the_same_read_box(client, alice, bob):
    by_handle = _send(client, alice, "bob").json()
    by_at = _send(client, alice, "@bob").json()
    by_id = _send(client, alice, bob["chat_id"]).json()
    inbox = client.get("/v1/messages", headers=bob["headers"]).json()
    assert inbox["count"] == 3
    assert {m["id"] for m in inbox["messages"]} == {
        by_handle["id"], by_at["id"], by_id["id"]}


def test_an_unregistered_recipient_is_refused_not_swallowed(client, alice):
    res = _send(client, alice, "someone-who-never-registered")
    assert res.status_code == 400
    assert "unknown_recipients" in res.json()["detail"]


# Rule #1 — refuse rather than best-effort. A partially routable message must
# not be half-delivered: the engine's worst bugs were partial successes.

def test_a_partially_unknown_recipient_list_delivers_nothing(client, alice, bob):
    res = _send(client, alice, ["bob", "ghost"])
    assert res.status_code == 400
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 0
    assert client.get("/v1/messages?box=sent",
                      headers=alice["headers"]).json()["count"] == 0


def test_a_revoked_chat_is_not_a_silent_black_hole(client, alice, bob):
    from conftest import owner_headers
    client.delete(f"/v1/admin/chats/{bob['chat_id']}", headers=owner_headers())
    assert _send(client, alice, "bob").status_code == 400


# Trap 4 — self-addressing dropped on the floor. The engine sent it over the
# network to itself, the transport refused, and nobody heard the message die.

def test_a_chat_can_message_itself(client, alice):
    sent = _send(client, alice, "alice")
    assert sent.status_code == 201
    inbox = client.get("/v1/messages", headers=alice["headers"]).json()
    assert inbox["count"] == 1 and inbox["messages"][0]["from"] == "alice"


def test_duplicate_recipients_are_delivered_once_and_reported_once(client, alice, bob):
    """The reported recipients must match the deliveries actually created —
    a count that lies is how a silent drop hides."""
    sent = _send(client, alice, ["bob", "@bob", bob["chat_id"]]).json()
    assert sent["delivered_to"] == ["bob"]
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 1
    status = client.get(f"/v1/messages/{sent['id']}/status",
                        headers=alice["headers"]).json()
    assert len(status["deliveries"]) == 1


# Trap 5 — `from` was a label, not an address. A sub-session asked a question,
# the answer went to the machine's shared box, and the asker never saw it.
# Reported as the most profitable test of the whole list. It goes first.

def test_from_is_a_valid_reply_address(client, alice, bob):
    sent = _send(client, alice, "bob").json()
    received = client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"]).json()

    reply = _send(client, bob, received["from"], subject="re", body="answer",
                  in_reply_to=sent["id"])
    assert reply.status_code == 201

    back = client.get("/v1/messages", headers=alice["headers"]).json()
    assert back["count"] == 1 and back["messages"][0]["id"] == reply.json()["id"]


def test_from_chat_id_is_also_a_valid_reply_address(client, alice, bob):
    sent = _send(client, alice, "bob").json()
    received = client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"]).json()
    reply = _send(client, bob, received["from_chat_id"])
    assert reply.status_code == 201
    assert client.get("/v1/messages", headers=alice["headers"]).json()["count"] == 1


# Trap 3 — a mass operation scoped by an implicit default instead of by the
# caller. In the engine it archived the whole machine; here it would be a
# tenant-isolation breach. There is no bulk endpoint yet — this test states the
# invariant any future one must satisfy.

def test_acting_on_ones_own_mail_never_touches_another_chats(client, alice, bob, mallory):
    for _ in range(3):
        _send(client, alice, ["bob", "mallory"])
    for m in client.get("/v1/messages", headers=bob["headers"]).json()["messages"]:
        client.post(f"/v1/messages/{m['id']}/archive", headers=bob["headers"])
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 0
    assert client.get("/v1/messages", headers=mallory["headers"]).json()["count"] == 3
