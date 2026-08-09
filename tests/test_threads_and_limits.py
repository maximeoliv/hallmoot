"""Thread reconstruction, status ladder, and the abuse guards."""
import pytest


def _send(client, sender, **kw):
    res = client.post("/v1/messages", headers=sender["headers"],
                      json={"to": kw.pop("to", "bob"), "subject": kw.pop("subject", "s"),
                            "body": kw.pop("body", "b"), **kw})
    assert res.status_code == 201, res.text
    return res.json()


def test_three_level_thread_is_ordered_and_shared(client, alice, bob):
    m1 = _send(client, alice, to="bob", subject="q", body="question")
    m2 = _send(client, bob, to="alice", subject="re: q", body="answer", in_reply_to=m1["id"])
    m3 = _send(client, alice, to="bob", subject="re: q", body="thanks", in_reply_to=m2["id"])

    assert m1["thread_id"] == m2["thread_id"] == m3["thread_id"]
    thread = client.get(f"/v1/threads/{m1['thread_id']}", headers=bob["headers"]).json()
    assert [m["body"] for m in thread["messages"]] == ["question", "answer", "thanks"]


def test_replying_marks_the_parent_replied(client, alice, bob):
    m1 = _send(client, alice, to="bob")
    _send(client, bob, to="alice", in_reply_to=m1["id"])
    status = client.get(f"/v1/messages/{m1['id']}/status", headers=alice["headers"]).json()
    assert status["deliveries"][0]["status"] == "replied"


def test_status_never_downgrades(client, alice, bob):
    """Once replied, reading the parent again must not drop it back to read."""
    m1 = _send(client, alice, to="bob")
    _send(client, bob, to="alice", in_reply_to=m1["id"])
    client.get(f"/v1/messages/{m1['id']}", headers=bob["headers"])
    status = client.get(f"/v1/messages/{m1['id']}/status", headers=alice["headers"]).json()
    assert status["deliveries"][0]["status"] == "replied"


def test_rate_limit_kicks_in(make_client):
    from conftest import enroll
    client = make_client(rate_limit=3)
    alice, _ = enroll(client, "alice"), enroll(client, "bob")
    codes = [client.post("/v1/messages", headers=alice["headers"],
                         json={"to": "bob", "subject": "s", "body": "b"}).status_code
             for _ in range(6)]
    assert codes[:3] == [201, 201, 201]
    assert 429 in codes[3:]


def test_oversized_body_is_refused(make_client):
    from conftest import enroll
    client = make_client(max_body=2048)
    alice, _ = enroll(client, "alice"), enroll(client, "bob")
    res = client.post("/v1/messages", headers=alice["headers"],
                      json={"to": "bob", "subject": "s", "body": "x" * 5000})
    assert res.status_code in (413, 422)


@pytest.mark.parametrize("payload", [
    {"to": "bob", "subject": "s", "body": "b", "unexpected": 1},
    {"to": "bob", "subject": "", "body": "b"},
    {"to": [], "subject": "s", "body": "b"},
    {"to": "bob", "subject": "s", "body": "b", "priority": "catastrophic"},
])
def test_malformed_payloads_are_rejected(client, alice, bob, payload):
    assert client.post("/v1/messages", headers=alice["headers"],
                       json=payload).status_code == 422


def test_pagination_is_bounded(client, alice, bob):
    assert client.get("/v1/messages?limit=9999", headers=bob["headers"]).status_code == 422


def test_a_flood_from_one_address_is_capped(make_client, monkeypatch):
    """Per-IP ceiling: the per-token bucket does nothing against unauthenticated
    traffic once the instance faces the internet."""
    from app import config
    from conftest import enroll
    monkeypatch.setattr(config, "RATE_LIMIT_PER_IP_PER_MIN", 5)
    client = make_client()
    codes = [client.get("/v1/directory").status_code for _ in range(9)]
    assert codes[:5] != [429] * 5      # the first few get through to auth
    assert 429 in codes                 # then the address itself is throttled


def test_health_is_never_throttled(make_client, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "RATE_LIMIT_PER_IP_PER_MIN", 2)
    client = make_client()
    assert all(client.get("/healthz").status_code == 200 for _ in range(6))
