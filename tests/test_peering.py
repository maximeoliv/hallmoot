"""Two instances that agree to talk — pairing, exposure, revocation.

Run against two real servers, because peering is the one thing that cannot be
tested inside a single process: the whole point is that the other side is
somebody else's machine, reachable only over HTTP, trusted only as far as the
token it presents.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _call(url, body=None, token=None, method="GET"):
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


class Instance:
    """One person's instance, with its own database, port and owner token."""

    def __init__(self, tmp_path, name):
        self.name = name
        self.owner = f"owner-{name}"
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = {**os.environ, "MOOT_DB_PATH": str(tmp_path / name / "db.sqlite3"),
               "MOOT_OWNER_TOKEN": self.owner, "MOOT_PUBLIC_URL": self.base,
               "PYTHONPATH": str(ROOT)}
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
        python = ROOT / ".venv" / "bin" / "python"
        self.proc = subprocess.Popen(
            [str(python if python.exists() else sys.executable), "-m", "uvicorn",
             "app.asgi:app", "--host", "127.0.0.1", "--port", str(self.port),
             "--log-level", "warning"],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(self.base + "/healthz", timeout=1)
                return
            except (urllib.error.URLError, ConnectionError):
                time.sleep(0.1)
        self.proc.kill()
        raise RuntimeError(f"instance {name} n'a pas démarré")

    def call(self, path, body=None, token=None, method="GET"):
        return _call(self.base + path, body, token or self.owner, method)

    def enroll(self, handle):
        _, inv = self.call("/v1/admin/invites", {"note": handle}, method="POST")
        _, chat = _call(f"{self.base}/v1/register", {
            "invite_code": inv["invite_code"], "handle": handle,
            "display_name": handle, "client": "test"}, None, "POST")
        return chat

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)


@pytest.fixture(scope="module")
def two_instances(tmp_path_factory):
    root = tmp_path_factory.mktemp("peering")
    alice = Instance(root, "chez-alice")
    bob = Instance(root, "chez-bob")
    yield alice, bob
    alice.stop()
    bob.stop()


def test_pairing_needs_an_invitation_from_the_other_side(two_instances):
    alice, bob = two_instances
    status, _ = bob.call("/v1/admin/peers/accept", {
        "alias": "chez-alice", "base_url": alice.base,
        "invite_code": "invitation-inventee"}, method="POST")
    assert status == 502  # the handshake was refused by Alice
    _, peers = bob.call("/v1/admin/peers")
    assert peers["count"] == 0


def test_a_full_pairing_leaves_both_sides_active_and_exposing_nothing(two_instances):
    alice, bob = two_instances
    _, invite = alice.call("/v1/admin/peers/invite", {"alias": "chez-bob"}, method="POST")
    status, paired = bob.call("/v1/admin/peers/accept", {
        "alias": "chez-alice", "base_url": alice.base,
        "invite_code": invite["invite_code"]}, method="POST")
    assert status == 201 and paired["state"] == "active"

    _, bobs = bob.call("/v1/admin/peers")
    _, alices = alice.call("/v1/admin/peers")
    assert [p["alias"] for p in bobs["peers"]] == ["chez-alice"]
    assert [p["alias"] for p in alices["peers"]] == ["chez-bob"]
    # the load-bearing default: a fresh pairing lets nothing through
    assert bobs["peers"][0]["exposed_chats"] == []
    assert alices["peers"][0]["exposed_chats"] == []


def test_an_invitation_is_single_use(two_instances):
    alice, bob = two_instances
    _, invite = alice.call("/v1/admin/peers/invite", {"alias": "rejouee"}, method="POST")
    first, _ = bob.call("/v1/admin/peers/accept", {
        "alias": "alice-1", "base_url": alice.base,
        "invite_code": invite["invite_code"]}, method="POST")
    second, _ = bob.call("/v1/admin/peers/accept", {
        "alias": "alice-2", "base_url": alice.base,
        "invite_code": invite["invite_code"]}, method="POST")
    assert first == 201 and second == 502


def test_exposing_a_chat_is_explicit_and_reversible(two_instances):
    alice, bob = two_instances
    alice.enroll("cowork")
    _, invite = alice.call("/v1/admin/peers/invite", {"alias": "expo"}, method="POST")
    bob.call("/v1/admin/peers/accept", {"alias": "alice-expo", "base_url": alice.base,
                                        "invite_code": invite["invite_code"]}, method="POST")

    status, _ = alice.call("/v1/admin/peers/expo/expose", {"chat": "cowork"}, method="POST")
    assert status == 200
    _, peers = alice.call("/v1/admin/peers")
    exposed = next(p for p in peers["peers"] if p["alias"] == "expo")["exposed_chats"]
    assert exposed == ["cowork"]

    status, _ = alice.call("/v1/admin/peers/expo/expose/cowork", method="DELETE")
    assert status == 200
    _, peers = alice.call("/v1/admin/peers")
    assert next(p for p in peers["peers"] if p["alias"] == "expo")["exposed_chats"] == []


def test_exposing_an_unknown_chat_is_refused(two_instances):
    alice, bob = two_instances
    _, invite = alice.call("/v1/admin/peers/invite", {"alias": "fantome"}, method="POST")
    bob.call("/v1/admin/peers/accept", {"alias": "alice-fantome", "base_url": alice.base,
                                        "invite_code": invite["invite_code"]}, method="POST")
    status, _ = alice.call("/v1/admin/peers/fantome/expose", {"chat": "personne"}, method="POST")
    assert status == 404


def test_revocation_is_unilateral_and_immediate(two_instances):
    alice, bob = two_instances
    _, invite = alice.call("/v1/admin/peers/invite", {"alias": "acouper"}, method="POST")
    bob.call("/v1/admin/peers/accept", {"alias": "alice-acouper", "base_url": alice.base,
                                        "invite_code": invite["invite_code"]}, method="POST")

    status, _ = alice.call("/v1/admin/peers/acouper", method="DELETE")
    assert status == 200
    _, peers = alice.call("/v1/admin/peers")
    cut = next(p for p in peers["peers"] if p["alias"] == "acouper")
    assert cut["state"] == "revoked" and cut["exposed_chats"] == []
    # and it cannot be operated any more
    assert alice.call("/v1/admin/peers/acouper/expose", {"chat": "cowork"},
                      method="POST")[0] == 404


def test_peering_is_owner_only(two_instances):
    alice, _ = two_instances
    chat = alice.enroll("simple-chat")
    status, _ = alice.call("/v1/admin/peers/invite", {"alias": "x"},
                           token=chat["chat_token"], method="POST")
    assert status == 403
    assert alice.call("/v1/admin/peers", token=chat["chat_token"])[0] == 403


def test_a_plaintext_peer_url_is_refused(two_instances):
    alice, bob = two_instances
    status, body = bob.call("/v1/admin/peers/accept", {
        "alias": "en-clair", "base_url": "http://exemple.test",
        "invite_code": "x" * 20}, method="POST")
    assert status == 400 and "https" in body["detail"]


def _paired(alice, bob, alias):
    """Pair the two instances under a fresh alias on each side."""
    _, invite = alice.call("/v1/admin/peers/invite", {"alias": alias}, method="POST")
    status, _ = bob.call("/v1/admin/peers/accept", {
        "alias": f"a-{alias}", "base_url": alice.base,
        "invite_code": invite["invite_code"]}, method="POST")
    assert status == 201
    return alias, f"a-{alias}"


def test_a_message_crosses_and_says_who_vouches_for_it(two_instances):
    """The address a recipient sees carries both halves of the truth: the peer
    alias is proven, the member name is that peer's claim."""
    alice, bob = two_instances
    here, there = _paired(alice, bob, "livraison")
    a_chat = alice.enroll("alice-chat")
    b_chat = bob.enroll("bob-chat")
    alice.call(f"/v1/admin/peers/{here}/expose", {"chat": "alice-chat"}, method="POST")
    bob.call(f"/v1/admin/peers/{there}/expose", {"chat": "bob-chat"}, method="POST")

    status, sent = bob.call("/v1/messages", {
        "to": f"alice-chat@{there}", "subject": "bonjour d'à côté",
        "body": "premier message entre deux instances"},
        token=b_chat["chat_token"], method="POST")
    assert status == 201, sent
    assert sent["delivered_to"] == [f"alice-chat@{there}"]

    _, inbox = alice.call("/v1/messages", token=a_chat["chat_token"])
    assert inbox["count"] == 1
    got = inbox["messages"][0]
    assert got["from"] == f"bob-chat@{here}"

    _, full = alice.call(f"/v1/messages/{got['id']}", token=a_chat["chat_token"])
    assert full["body"] == "premier message entre deux instances"


def test_a_chat_that_was_not_exposed_cannot_be_reached(two_instances):
    """The default that carries the whole model: pairing alone opens nothing."""
    alice, bob = two_instances
    here, there = _paired(alice, bob, "ferme")
    alice.enroll("secret-chat")
    b_chat = bob.enroll("bob-ferme")

    status, body = bob.call("/v1/messages", {
        "to": f"secret-chat@{there}", "subject": "s", "body": "b"},
        token=b_chat["chat_token"], method="POST")
    assert status == 502
    assert "404" in str(body["detail"]["reason"])


def test_a_revoked_peer_stops_resolving(two_instances):
    alice, bob = two_instances
    here, there = _paired(alice, bob, "coupure")
    alice.enroll("cible")
    alice.call(f"/v1/admin/peers/{here}/expose", {"chat": "cible"}, method="POST")
    b_chat = bob.enroll("bob-coupure")

    assert bob.call("/v1/messages", {"to": f"cible@{there}", "subject": "s", "body": "avant"},
                    token=b_chat["chat_token"], method="POST")[0] == 201
    bob.call(f"/v1/admin/peers/{there}", method="DELETE")
    status, body = bob.call("/v1/messages", {
        "to": f"cible@{there}", "subject": "s", "body": "après"},
        token=b_chat["chat_token"], method="POST")
    assert status == 400
    assert body["detail"]["unknown_recipients"][0]["reason"] == "unknown_peer"


def test_a_peer_cannot_forge_a_third_partys_address(two_instances):
    """A sender carrying an @ would let a peer speak as someone else's member."""
    alice, bob = two_instances
    here, _ = _paired(alice, bob, "usurpation")
    alice.enroll("victime")
    alice.call(f"/v1/admin/peers/{here}/expose", {"chat": "victime"}, method="POST")
    _, peers = alice.call("/v1/admin/peers")
    peer = next(p for p in peers["peers"] if p["alias"] == here)

    # forge directly against the inbox, without a valid peer token
    status, _ = _call(f"{alice.base}/v1/peer/inbox", {
        "from_sender": "quelquun@ailleurs", "to": "victime",
        "subject": "s", "body": "b"}, "jeton-invente", "POST")
    assert status == 401, "un jeton inventé ne doit rien pouvoir"
    assert peer["state"] == "active"


def test_the_inbox_needs_a_valid_peer_token(two_instances):
    alice, _ = two_instances
    status, _ = _call(f"{alice.base}/v1/peer/inbox", {
        "from_sender": "x", "to": "y", "subject": "s", "body": "b"}, None, "POST")
    assert status == 401


def test_mixing_local_and_remote_recipients_is_refused(two_instances):
    alice, bob = two_instances
    here, there = _paired(alice, bob, "melange")
    alice.enroll("distante")
    alice.call(f"/v1/admin/peers/{here}/expose", {"chat": "distante"}, method="POST")
    b_chat = bob.enroll("bob-melange")
    bob.enroll("locale")

    status, body = bob.call("/v1/messages", {
        "to": ["locale", f"distante@{there}"], "subject": "s", "body": "b"},
        token=b_chat["chat_token"], method="POST")
    assert status == 400
    assert "pair" in body["detail"]


def test_nothing_is_recorded_when_the_peer_refuses(two_instances):
    """Push first, record second: a local copy of an undelivered message is the
    silent failure in its purest form."""
    alice, bob = two_instances
    here, there = _paired(alice, bob, "refus")
    b_chat = bob.enroll("bob-refus")

    status, _ = bob.call("/v1/messages", {
        "to": f"inexistante@{there}", "subject": "s", "body": "b"},
        token=b_chat["chat_token"], method="POST")
    assert status == 502
    _, sent = bob.call("/v1/messages?box=sent", token=b_chat["chat_token"])
    assert sent["count"] == 0


def test_a_pending_invitation_is_visible(two_instances):
    """You invited someone and they have not answered: nothing else in the
    system would show that you did."""
    alice, _ = two_instances
    alice.call("/v1/admin/peers/invite", {"alias": "en-attente"}, method="POST")
    _, listed = alice.call("/v1/admin/peers")
    assert "en-attente" in [i["alias"] for i in listed["pending_invites"]]
    assert "en-attente" not in [p["alias"] for p in listed["peers"]]
