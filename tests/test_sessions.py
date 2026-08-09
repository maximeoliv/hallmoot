"""Sub-addressing: one conversation inside a client.

MCP hands the server no conversation identifier, so a client declares its own
label and it becomes a sub-address: `@cowork/planning`.

This is the exact ground where the forked engine lost messages twice, so the
two guarantees below come before anything else:

* **Trap 2 — an alias that resolves to a box nobody reads.** Here a session is a
  label on a delivery, never a separate mailbox: the parent chat sees all of its
  mail, always. There is no box that only a sub-address can open.
* **Trap 5 — `from` as a label rather than a reply address.** Whatever `from`
  says must be usable verbatim as `to`, and land back in the same conversation.
"""


def _send(client, sender, to, **kw):
    return client.post("/v1/messages", headers=sender["headers"],
                       json={"to": to, "subject": kw.pop("subject", "s"),
                             "body": kw.pop("body", "b"), **kw})


def _open(client, chat, label):
    res = client.post("/v1/sessions", headers=chat["headers"], json={"label": label})
    assert res.status_code == 201, res.text
    return res.json()


# ── trap 2: no unread box, ever ────────────────────────────────────────

def test_session_mail_is_always_visible_to_the_parent_chat(client, alice, bob):
    _open(client, bob, "cadrage")
    sent = _send(client, alice, "bob/cadrage")
    assert sent.status_code == 201

    # Bob, who never mentions the session, still sees it. This is the guarantee.
    inbox = client.get("/v1/messages", headers=bob["headers"]).json()
    assert inbox["count"] == 1
    assert inbox["messages"][0]["to"] == ["bob/cadrage"]

    scoped = client.get("/v1/messages?session=cadrage", headers=bob["headers"]).json()
    assert scoped["count"] == 1


def test_closing_a_session_does_not_swallow_its_mail(client, alice, bob):
    _open(client, bob, "cadrage")
    _send(client, alice, "bob/cadrage")
    assert client.delete("/v1/sessions/cadrage", headers=bob["headers"]).status_code == 200
    # the conversation is gone; the message it received is not
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 1
    # and it is no longer addressable — loudly
    assert _send(client, alice, "bob/cadrage").status_code == 400


def test_an_unknown_session_is_refused_not_delivered_to_the_parent(client, alice, bob):
    """Best-effort routing is how the engine lost a message: the sender saw a
    success, the mail went somewhere else."""
    res = _send(client, alice, "bob/jamais-ouverte")
    assert res.status_code == 400
    assert res.json()["detail"]["unknown_recipients"][0]["reason"] == "unknown_session"
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 0


# ── trap 5: `from` is an address you can reply to ──────────────────────

def test_from_of_a_session_message_is_a_working_reply_address(client, alice, bob):
    _open(client, alice, "cadrage")
    sent = _send(client, alice, "bob", as_session="cadrage").json()

    received = client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"]).json()
    assert received["from"] == "alice/cadrage"

    # reply to exactly what `from` said, with no interpretation
    reply = _send(client, bob, received["from"], subject="re", body="pong")
    assert reply.status_code == 201

    back = client.get("/v1/messages?session=cadrage", headers=alice["headers"]).json()
    assert back["count"] == 1 and back["messages"][0]["id"] == reply.json()["id"]


def test_two_conversations_of_one_client_do_not_mix(client, alice, bob):
    _open(client, bob, "projet-a")
    _open(client, bob, "projet-b")
    _send(client, alice, "bob/projet-a", body="pour A")
    _send(client, alice, "bob/projet-b", body="pour B")

    a = client.get("/v1/messages?session=projet-a", headers=bob["headers"]).json()
    b = client.get("/v1/messages?session=projet-b", headers=bob["headers"]).json()
    assert a["count"] == b["count"] == 1
    assert a["messages"][0]["id"] != b["messages"][0]["id"]
    # and the client still sees both at once
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 2


# ── the rest of the model still holds ──────────────────────────────────

def test_sessions_are_listed_and_addressable_by_others(client, alice, bob):
    _open(client, bob, "cadrage")
    listed = client.get("/v1/sessions?chat=bob", headers=alice["headers"]).json()
    assert [s["address"] for s in listed["sessions"]] == ["bob/cadrage"]


def test_reopening_a_label_returns_the_same_session(client, bob):
    first = _open(client, bob, "cadrage")
    again = client.post("/v1/sessions", headers=bob["headers"],
                        json={"label": "CADRAGE"}).json()
    assert again["id"] == first["id"]
    assert again["reopened"] is True


def test_a_session_belongs_to_its_chat_only(client, alice, bob):
    _open(client, bob, "cadrage")
    # alice cannot send *as* bob's session
    res = _send(client, alice, "bob", as_session="cadrage")
    assert res.status_code == 404
    # nor list it as hers
    assert client.get("/v1/messages?session=cadrage",
                      headers=alice["headers"]).status_code == 404


def test_labels_are_normalized_the_way_handles_are(client, bob):
    opened = client.post("/v1/sessions", headers=bob["headers"],
                         json={"label": "@Cadrage_2026"}).json()
    assert opened["label"] == "cadrage_2026"
    assert client.post("/v1/sessions", headers=bob["headers"],
                       json={"label": "espace interdit"}).status_code == 422


def test_isolation_survives_sub_addressing(client, alice, bob, mallory):
    _open(client, bob, "cadrage")
    sent = _send(client, alice, "bob/cadrage", body="privé").json()
    assert client.get(f"/v1/messages/{sent['id']}",
                      headers=mallory["headers"]).status_code == 404
