"""Delivery lifecycle: statuses, receipts, unsend, edit, archive.

Ported wholesale from the engine's state machine (delivered → read → replied →
closed, never downgrading), which is the part of it worth keeping.
"""


def _send(client, sender, to="bob", subject="s", body="b", **kw):
    res = client.post("/v1/messages", headers=sender["headers"],
                      json={"to": to, "subject": subject, "body": body, **kw})
    assert res.status_code == 201, res.text
    return res.json()["id"]


def test_send_then_read_flips_the_status(client, alice, bob):
    mid = _send(client, alice)
    before = client.get(f"/v1/messages/{mid}/status", headers=alice["headers"]).json()
    assert before["deliveries"][0]["status"] == "delivered"
    assert before["deliveries"][0]["read_at"] is None

    client.get(f"/v1/messages/{mid}", headers=bob["headers"])

    after = client.get(f"/v1/messages/{mid}/status", headers=alice["headers"]).json()
    assert after["deliveries"][0]["status"] == "read"
    assert after["deliveries"][0]["read_at"] is not None


def test_peek_does_not_mark_read(client, alice, bob):
    mid = _send(client, alice)
    client.get(f"/v1/messages/{mid}?peek=true", headers=bob["headers"])
    status = client.get(f"/v1/messages/{mid}/status", headers=alice["headers"]).json()
    assert status["deliveries"][0]["status"] == "delivered"


def test_unsend_works_before_read(client, alice, bob):
    mid = _send(client, alice)
    assert client.delete(f"/v1/messages/{mid}", headers=alice["headers"]).status_code == 200
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 0
    assert client.get(f"/v1/messages/{mid}", headers=bob["headers"]).status_code == 410


def test_unsend_refused_after_read(client, alice, bob):
    mid = _send(client, alice)
    client.get(f"/v1/messages/{mid}", headers=bob["headers"])
    res = client.delete(f"/v1/messages/{mid}", headers=alice["headers"])
    assert res.status_code == 409
    assert res.json()["detail"]["reason"] == "already_read"
    assert client.get(f"/v1/messages/{mid}", headers=bob["headers"]).status_code == 200


def test_edit_before_read_then_refused_after(client, alice, bob):
    mid = _send(client, alice, body="typo")
    assert client.patch(f"/v1/messages/{mid}", headers=alice["headers"],
                        json={"body": "fixed"}).status_code == 200
    got = client.get(f"/v1/messages/{mid}", headers=bob["headers"]).json()
    assert got["body"] == "fixed" and got["edited_at"] is not None

    res = client.patch(f"/v1/messages/{mid}", headers=alice["headers"], json={"body": "again"})
    assert res.status_code == 409


def test_only_the_sender_can_unsend_or_edit(client, alice, bob):
    mid = _send(client, alice)
    assert client.delete(f"/v1/messages/{mid}", headers=bob["headers"]).status_code == 404
    assert client.patch(f"/v1/messages/{mid}", headers=bob["headers"],
                        json={"body": "nope"}).status_code == 404


def test_archive_moves_it_out_of_the_inbox(client, alice, bob):
    mid = _send(client, alice)
    assert client.post(f"/v1/messages/{mid}/archive",
                       headers=bob["headers"]).status_code == 200
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 0
    assert client.get("/v1/messages?box=archive", headers=bob["headers"]).json()["count"] == 1
    # archiving twice is not a silent success
    assert client.post(f"/v1/messages/{mid}/archive",
                       headers=bob["headers"]).status_code == 404


def test_unknown_recipient_is_rejected(client, alice, bob):
    res = client.post("/v1/messages", headers=alice["headers"],
                      json={"to": ["bob", "ghost"], "subject": "s", "body": "b"})
    assert res.status_code == 400
    unknown = res.json()["detail"]["unknown_recipients"]
    assert [u["address"] for u in unknown] == ["ghost"]
    assert unknown[0]["reason"] == "unknown_chat"


def test_events_report_new_mail(client, alice, bob):
    mid = _send(client, alice)
    res = client.get("/v1/events?since=0&timeout=0", headers=bob["headers"]).json()
    assert [e["type"] for e in res["events"]] == ["message.received"]
    assert res["events"][0]["message_id"] == mid
    # the cursor drains the queue
    assert client.get(f"/v1/events?since={res['cursor']}&timeout=0",
                      headers=bob["headers"]).json()["count"] == 0
