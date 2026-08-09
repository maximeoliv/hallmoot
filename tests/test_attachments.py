"""Attachments — and the original engine's first trap before anything else.

The forked engine accepted `--attach a --attach b` and kept only the **last**
one: four files sent, one delivered, no error anywhere. Hence the rule tested
here — N sent means exactly N received, with matching checksums, never "at
least one".

The rest of this file is about the two other ways file handling goes wrong: a
filename that reaches the filesystem, and a content type the sender got to
choose.
"""
import hashlib


def upload(client, chat, name, content: bytes, content_type="application/octet-stream"):
    res = client.post("/v1/blobs", headers=chat["headers"],
                      files={"file": (name, content, content_type)})
    assert res.status_code == 201, res.text
    return res.json()


def send(client, sender, to="bob", attachments=None, **kw):
    return client.post("/v1/messages", headers=sender["headers"],
                       json={"to": to, "subject": kw.pop("subject", "s"),
                             "body": kw.pop("body", "b"),
                             "attachments": attachments or [], **kw})


# ── trap 1: N sent, exactly N received ─────────────────────────────────

def test_every_attachment_arrives_with_matching_bytes(client, alice, bob):
    files = {f"fichier-{i}.bin": bytes([i]) * (100 + i) for i in range(4)}
    blobs = [upload(client, alice, name, data) for name, data in files.items()]

    sent = send(client, alice, attachments=[b["blob_id"] for b in blobs]).json()
    assert len(sent["attachments"]) == 4

    received = client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"]).json()
    assert len(received["attachments"]) == 4, "N envoyées doit valoir exactement N reçues"
    assert {a["filename"] for a in received["attachments"]} == set(files)

    for att in received["attachments"]:
        got = client.get(f"/v1/messages/{sent['id']}/attachments/{att['blob_id']}",
                         headers=bob["headers"])
        assert got.status_code == 200
        original = files[att["filename"]]
        assert got.content == original
        assert att["sha256"] == hashlib.sha256(original).hexdigest()


def test_one_bad_attachment_sends_nothing(client, alice, bob):
    """All-or-nothing: a partially valid list must not deliver a partial message."""
    good = upload(client, alice, "ok.txt", b"contenu")
    res = send(client, alice, attachments=[good["blob_id"], "blob-inexistant"])
    assert res.status_code == 400
    assert {b["reason"] for b in res.json()["detail"]["bad_attachments"]} == {"unknown_blob"}
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 0
    # the good blob is still unattached, so it can be reused
    assert send(client, alice, attachments=[good["blob_id"]]).status_code == 201


def test_a_blob_cannot_be_attached_twice(client, alice, bob):
    blob = upload(client, alice, "once.txt", b"une seule fois")
    assert send(client, alice, attachments=[blob["blob_id"]]).status_code == 201
    again = send(client, alice, attachments=[blob["blob_id"]])
    assert again.status_code == 400
    assert again.json()["detail"]["bad_attachments"][0]["reason"] == "already_attached"


def test_the_same_id_twice_in_one_message_is_refused(client, alice):
    blob = upload(client, alice, "dup.txt", b"x")
    res = send(client, alice, attachments=[blob["blob_id"], blob["blob_id"]])
    assert res.status_code == 400


# ── ownership and isolation ────────────────────────────────────────────

def test_you_can_only_attach_your_own_uploads(client, alice, bob, mallory):
    blob = upload(client, mallory, "a-elle.txt", b"pas la tienne")
    res = send(client, alice, attachments=[blob["blob_id"]])
    assert res.status_code == 400
    assert res.json()["detail"]["bad_attachments"][0]["reason"] == "unknown_blob"


def test_a_third_party_cannot_download(client, alice, bob, mallory):
    blob = upload(client, alice, "prive.txt", b"secret")
    sent = send(client, alice, attachments=[blob["blob_id"]]).json()
    res = client.get(f"/v1/messages/{sent['id']}/attachments/{blob['blob_id']}",
                     headers=mallory["headers"])
    assert res.status_code == 404 and b"secret" not in res.content


def test_recalling_a_message_takes_its_attachments_with_it(client, alice, bob):
    blob = upload(client, alice, "rappel.txt", b"a rappeler")
    sent = send(client, alice, attachments=[blob["blob_id"]]).json()
    assert client.delete(f"/v1/messages/{sent['id']}", headers=alice["headers"]).status_code == 200
    assert client.get(f"/v1/messages/{sent['id']}/attachments/{blob['blob_id']}",
                      headers=bob["headers"]).status_code == 404


# ── hostile input ──────────────────────────────────────────────────────

def test_a_filename_never_reaches_the_filesystem(client, alice, bob):
    """Content-addressed storage means the path is the hash. A traversal
    attempt survives only as a harmless display string."""
    blob = upload(client, alice, "../../../etc/passwd", b"tentative")
    assert blob["filename"] == "passwd"
    sent = send(client, alice, attachments=[blob["blob_id"]]).json()
    got = client.get(f"/v1/messages/{sent['id']}/attachments/{blob['blob_id']}",
                     headers=bob["headers"])
    assert got.content == b"tentative"


def test_a_declared_html_type_is_not_served_back_as_html(client, alice, bob):
    """A stored text/html served as text/html is a stored XSS. Everything
    leaves as an opaque download."""
    blob = upload(client, alice, "piege.html", b"<script>alert(1)</script>", "text/html")
    sent = send(client, alice, attachments=[blob["blob_id"]]).json()
    got = client.get(f"/v1/messages/{sent['id']}/attachments/{blob['blob_id']}",
                     headers=bob["headers"])
    assert got.headers["content-type"] == "application/octet-stream"
    assert got.headers["x-content-type-options"] == "nosniff"


def test_an_empty_upload_is_refused(client, alice):
    res = client.post("/v1/blobs", headers=alice["headers"],
                      files={"file": ("vide.txt", b"", "text/plain")})
    assert res.status_code == 400


def test_identical_bytes_are_stored_once(client, alice):
    same = b"exactement les memes octets"
    a = upload(client, alice, "un.txt", same)
    b = upload(client, alice, "deux.txt", same)
    assert a["sha256"] == b["sha256"] and a["blob_id"] != b["blob_id"]
    stored = list((client.app.state.blob_dir / a["sha256"][:2]).glob(a["sha256"]))
    assert len(stored) == 1


def test_upload_requires_a_chat_token(client):
    from conftest import owner_headers
    assert client.post("/v1/blobs", files={"file": ("x.txt", b"y")}).status_code == 401
    assert client.post("/v1/blobs", headers=owner_headers(),
                       files={"file": ("x.txt", b"y")}).status_code == 403


def test_attachments_live_beside_their_own_database(client, alice, tmp_path):
    """Regression: the blob directory used to come from a module-level default,
    so an instance with a custom database path stored its files elsewhere."""
    blob = upload(client, alice, "ici.txt", b"chez moi")
    expected = client.app.state.blob_dir / blob["sha256"][:2] / blob["sha256"]
    assert expected.exists()
    assert client.app.state.blob_dir.parent == tmp_path


def test_attach_file_over_mcp_round_trips(client, alice, bob):
    """The path an MCP client actually takes: base64 in a tool call, then the
    blob id in send()."""
    import base64
    import json as _json

    def call(chat, tool, **args):
        res = client.post("/mcp", headers=chat["headers"], json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args}})
        payload = res.json()["result"]
        return _json.loads(payload["content"][0]["text"]), payload["isError"]

    blob, err = call(alice, "attach_file", filename="note.txt",
                     content_base64=base64.b64encode(b"contenu joint").decode())
    assert not err, blob
    sent, err = call(alice, "send", to="bob", subject="avec pj", body="voir pièce jointe",
                     attachments=[blob["blob_id"]])
    assert not err and len(sent["attachments"]) == 1

    read, _ = call(bob, "message_read", id=sent["id"])
    assert read["attachments"][0]["filename"] == "note.txt"
    got = client.get(read["attachments"][0]["download"], headers=bob["headers"])
    assert got.content == b"contenu joint"


def test_inline_upload_is_capped_below_the_multipart_limit(client, alice, monkeypatch):
    import base64
    from app import config
    monkeypatch.setattr(config, "MAX_INLINE_ATTACHMENT_BYTES", 64)
    res = client.post("/v1/blobs/inline", headers=alice["headers"], json={
        "filename": "gros.bin", "content_base64": base64.b64encode(b"x" * 200).decode()})
    assert res.status_code == 413


def test_an_attachment_can_be_read_through_mcp(client, alice, bob):
    """Otherwise a browser-based client sees a file it can never open: only
    /mcp is published, /v1 is unreachable from outside."""
    import base64
    import json as _json

    def call(chat, tool, **args):
        payload = client.post("/mcp", headers=chat["headers"], json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args}}).json()["result"]
        return _json.loads(payload["content"][0]["text"]), payload["isError"]

    blob = upload(client, alice, "note.txt", "café ☕".encode())
    sent = send(client, alice, attachments=[blob["blob_id"]]).json()

    got, err = call(bob, "attachment_read", message_id=sent["id"], blob_id=blob["blob_id"])
    assert not err and got["encoding"] == "utf-8" and got["content"] == "café ☕"

    binary = upload(client, alice, "img.bin", bytes(range(256)))
    sent2 = send(client, alice, attachments=[binary["blob_id"]]).json()
    got2, _ = call(bob, "attachment_read", message_id=sent2["id"], blob_id=binary["blob_id"])
    assert got2["encoding"] == "base64"
    assert base64.b64decode(got2["content"]) == bytes(range(256))


def test_a_third_party_cannot_read_an_attachment_through_mcp(client, alice, bob, mallory):
    blob = upload(client, alice, "prive.txt", b"secret")
    sent = send(client, alice, attachments=[blob["blob_id"]]).json()
    res = client.get(f"/v1/messages/{sent['id']}/attachments/{blob['blob_id']}/content",
                     headers=mallory["headers"])
    assert res.status_code == 404 and b"secret" not in res.content


def test_a_large_attachment_refuses_inline_and_points_at_the_download(client, alice, bob,
                                                                     monkeypatch):
    from app import config
    blob = upload(client, alice, "gros.bin", b"x" * 5000)
    sent = send(client, alice, attachments=[blob["blob_id"]]).json()
    monkeypatch.setattr(config, "MAX_INLINE_ATTACHMENT_BYTES", 1000)
    res = client.get(f"/v1/messages/{sent['id']}/attachments/{blob['blob_id']}/content",
                     headers=bob["headers"])
    assert res.status_code == 413
    assert res.json()["detail"]["download"].endswith(blob["blob_id"])


def test_a_realistic_attachment_fits_through_a_tool_call(client, alice, bob):
    """Regression: the message-body ceiling (256 Ko) also applied to /mcp, so
    anything past ~190 Ko of real bytes could not be attached from a browser
    client at all — and it failed by dropping the connection, not by saying so.
    """
    import base64
    import json as _json
    payload = base64.b64encode(b"x" * 400_000).decode()   # ~533 Ko once encoded
    res = client.post("/mcp", headers=alice["headers"], json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "attach_file", "arguments": {
            "filename": "capture.png", "content_base64": payload}}})
    assert res.status_code == 200
    body = _json.loads(res.json()["result"]["content"][0]["text"])
    assert not res.json()["result"]["isError"], body
    assert body["size"] == 400_000


def test_beyond_the_inline_ceiling_the_refusal_is_explicit(client, alice):
    """Too big must be a readable error, not a mystery."""
    import base64
    from app import config
    payload = base64.b64encode(b"x" * (config.MAX_INLINE_ATTACHMENT_BYTES + 1000)).decode()
    res = client.post("/v1/blobs/inline", headers=alice["headers"], json={
        "filename": "trop-gros.bin", "content_base64": payload})
    assert res.status_code == 413
    assert "/v1/blobs" in res.json()["detail"]
