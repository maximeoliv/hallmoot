"""The audit trail records what happened — and nothing that would hurt if leaked.

A log is the easiest thing to ship somewhere else: to a monitoring stack, a
bug report, a support ticket. So it carries ids and handles, never message
content and never a credential.
"""
import json
import logging


def _lines(caplog):
    return [json.loads(r.message) for r in caplog.records
            if r.name == "hallmoot.audit"]


def test_actions_are_recorded(client, alice, bob, caplog):
    with caplog.at_level(logging.INFO, logger="hallmoot.audit"):
        sent = client.post("/v1/messages", headers=alice["headers"],
                           json={"to": "bob", "subject": "s", "body": "b"}).json()
        client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"])

    actions = {e["action"]: e for e in _lines(caplog)}
    assert actions["message.sent"]["actor"] == "alice"
    assert actions["message.sent"]["to"] == ["bob"]
    assert actions["message.sent"]["message_id"] == sent["id"]
    assert actions["message.read"]["actor"] == "bob"


def test_the_trail_never_carries_content_or_credentials(client, alice, bob, caplog):
    with caplog.at_level(logging.INFO, logger="hallmoot.audit"):
        sent = client.post("/v1/messages", headers=alice["headers"], json={
            "to": "bob", "subject": "OBJET-CONFIDENTIEL",
            "body": "CORPS-CONFIDENTIEL"}).json()
        client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"])
        client.patch(f"/v1/messages/{sent['id']}", headers=alice["headers"],
                     json={"body": "AUTRE-SECRET"})

    text = "\n".join(r.message for r in caplog.records)
    for forbidden in ("OBJET-CONFIDENTIEL", "CORPS-CONFIDENTIEL", "AUTRE-SECRET",
                      alice["chat_token"], bob["chat_token"]):
        assert forbidden not in text
    # the size is recorded, the content is not
    assert any(e.get("bytes") for e in _lines(caplog) if e["action"] == "message.sent")


def test_lifecycle_events_are_traced(client, alice, bob, caplog):
    from conftest import owner_headers
    with caplog.at_level(logging.INFO, logger="hallmoot.audit"):
        m = client.post("/v1/messages", headers=alice["headers"],
                        json={"to": "bob", "subject": "s", "body": "b"}).json()
        client.delete(f"/v1/messages/{m['id']}", headers=alice["headers"])
        client.delete(f"/v1/admin/chats/{bob['chat_id']}", headers=owner_headers())

    actions = {e["action"] for e in _lines(caplog)}
    assert {"message.sent", "message.recalled", "chat.revoked"} <= actions


def test_registration_is_traced_without_the_token(client, caplog):
    from conftest import enroll
    with caplog.at_level(logging.INFO, logger="hallmoot.audit"):
        chat = enroll(client, "newcomer")
    entry = next(e for e in _lines(caplog) if e["action"] == "chat.registered")
    assert entry["handle"] == "newcomer" and entry["chat_id"] == chat["chat_id"]
    assert chat["chat_token"] not in json.dumps(entry)
