"""Forgetting — the part of storage nobody writes until the disk is full.

Two very different behaviours share this file, and the difference matters:

* **Old messages** are deleted only when the owner configures a window. Silently
  deleting someone's mail is a worse failure than a database that grows.
* **Uploads that were never sent** expire on their own. Nobody sees them in an
  inbox, so nobody will ever come looking — they are invisible weight.
"""
from datetime import datetime, timedelta, timezone

from conftest import owner_headers


def _age_message(client, message_id, days):
    """Backdate a message the way real time would have."""
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    client.app.state.conn.execute("UPDATE messages SET created_at = ? WHERE id = ?",
                                  (old, message_id))


def _age_blob(client, blob_id, hours):
    old = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    client.app.state.conn.execute("UPDATE blobs SET created_at = ? WHERE id = ?",
                                  (old, blob_id))


def _send(client, sender, **kw):
    return client.post("/v1/messages", headers=sender["headers"],
                       json={"to": "bob", "subject": "s", "body": "b", **kw}).json()


def _upload(client, chat, name, content):
    return client.post("/v1/blobs", headers=chat["headers"],
                       files={"file": (name, content)}).json()


def test_nothing_is_forgotten_by_default(client, alice, bob):
    old = _send(client, alice)
    _age_message(client, old["id"], 3650)
    res = client.post("/v1/admin/retention", headers=owner_headers()).json()
    assert res["window_days"] == 0 and res["dropped"]["messages"] == 0
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 1


def test_a_configured_window_drops_old_mail_and_keeps_recent(client, alice, bob):
    old = _send(client, alice, body="vieux")
    recent = _send(client, alice, body="récent")
    _age_message(client, old["id"], 40)

    res = client.post("/v1/admin/retention?days=30", headers=owner_headers()).json()
    assert res["dropped"]["messages"] == 1

    left = client.get("/v1/messages", headers=bob["headers"]).json()
    assert [m["id"] for m in left["messages"]] == [recent["id"]]
    assert client.get(f"/v1/messages/{old['id']}", headers=bob["headers"]).status_code == 404


def test_dropping_a_message_takes_its_attachment_bytes(client, alice, bob):
    blob = _upload(client, alice, "vieux.txt", b"contenu ancien")
    sent = _send(client, alice, attachments=[blob["blob_id"]])
    stored = client.app.state.blob_dir / blob["sha256"][:2] / blob["sha256"]
    assert stored.exists()

    _age_message(client, sent["id"], 40)
    res = client.post("/v1/admin/retention?days=30", headers=owner_headers()).json()
    assert res["dropped"]["attachments"] == 1 and res["dropped"]["files"] == 1
    assert not stored.exists()


def test_shared_bytes_survive_while_another_message_needs_them(client, alice, bob):
    """Content-addressed storage means two messages can share one file. Deleting
    one must not gut the other."""
    same = b"octets partages"
    old_blob = _upload(client, alice, "a.txt", same)
    new_blob = _upload(client, alice, "b.txt", same)
    assert old_blob["sha256"] == new_blob["sha256"]
    old_msg = _send(client, alice, attachments=[old_blob["blob_id"]])
    new_msg = _send(client, alice, attachments=[new_blob["blob_id"]])
    _age_message(client, old_msg["id"], 40)

    client.post("/v1/admin/retention?days=30", headers=owner_headers())

    stored = client.app.state.blob_dir / new_blob["sha256"][:2] / new_blob["sha256"]
    assert stored.exists(), "les octets encore référencés ne doivent pas disparaître"
    read = client.get(f"/v1/messages/{new_msg['id']}/attachments/{new_blob['blob_id']}",
                      headers=bob["headers"])
    assert read.status_code == 200 and read.content == same


def test_uploads_that_were_never_sent_expire_on_their_own(client, alice, bob):
    forgotten = _upload(client, alice, "jamais-envoye.txt", b"perdu")
    fresh = _upload(client, alice, "tout-neuf.txt", b"encore utile")
    _age_blob(client, forgotten["blob_id"], 48)

    res = client.post("/v1/admin/retention", headers=owner_headers()).json()
    assert res["dropped"]["orphan_blobs"] == 1
    assert not (client.app.state.blob_dir / forgotten["sha256"][:2]
                / forgotten["sha256"]).exists()

    # the fresh one is untouched, and still attachable
    assert (client.app.state.blob_dir / fresh["sha256"][:2] / fresh["sha256"]).exists()
    assert client.post("/v1/messages", headers=alice["headers"], json={
        "to": "bob", "subject": "s", "body": "b",
        "attachments": [fresh["blob_id"]]}).status_code == 201


def test_retention_is_owner_only(client, alice):
    assert client.post("/v1/admin/retention", headers=alice["headers"]).status_code == 403


def test_an_attached_upload_never_counts_as_an_orphan(client, alice, bob):
    blob = _upload(client, alice, "attache.txt", b"bien envoye")
    sent = _send(client, alice, attachments=[blob["blob_id"]])
    _age_blob(client, blob["blob_id"], 500)

    res = client.post("/v1/admin/retention", headers=owner_headers()).json()
    assert res["dropped"]["orphan_blobs"] == 0
    got = client.get(f"/v1/messages/{sent['id']}/attachments/{blob['blob_id']}",
                     headers=bob["headers"])
    assert got.status_code == 200
