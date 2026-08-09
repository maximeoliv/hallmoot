"""Several clients at once — the assumption nobody had tested.

Every other test drives the app in a single thread through the test client.
Production is uvicorn with SQLite in WAL mode and a handful of chats writing at
the same moment, which is where "database is locked" lives. This file runs a
real server and hits it from real threads.

It is slower than the rest of the suite on purpose: a load assumption verified
once a day beats one verified never.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
OWNER = "concurrency-owner-token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _call(url, body=None, token=None, method="GET"):
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(body).encode() if body else None)
    if body:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    port = _free_port()
    env = {**os.environ,
           "MOOT_DB_PATH": str(tmp_path_factory.mktemp("load") / "db.sqlite3"),
           "MOOT_OWNER_TOKEN": OWNER,
           "MOOT_RATE_LIMIT_PER_MIN": "100000",
           "MOOT_RATE_LIMIT_PER_IP_PER_MIN": "100000",
           "PYTHONPATH": str(ROOT)}
    python = ROOT / ".venv" / "bin" / "python"
    proc = subprocess.Popen(
        [str(python if python.exists() else sys.executable), "-m", "uvicorn",
         "app.asgi:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            break
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("le serveur n'a pas démarré")
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def _enroll(base, handle):
    _, inv = _call(f"{base}/v1/admin/invites", {"note": handle}, OWNER, "POST")
    _, chat = _call(f"{base}/v1/register", {
        "invite_code": inv["invite_code"], "handle": handle,
        "display_name": handle, "client": "load"}, None, "POST")
    return chat


@pytest.fixture(scope="module")
def peers(server):
    return _enroll(server, "sender"), _enroll(server, "receiver")


def test_simultaneous_senders_all_get_through(server, peers):
    """Forty writes from eight threads. Every one must be delivered, and none
    may fail on a lock: a message that returns 500 under load is a message the
    sender believes was lost — or worse, believes was sent."""
    sender, receiver = peers
    n = 40

    def send(i):
        return _call(f"{server}/v1/messages", {
            "to": "receiver", "subject": f"charge {i}", "body": f"message {i}"},
            sender["chat_token"], "POST")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(send, range(n)))

    codes = [code for code, _ in results]
    assert codes == [201] * n, f"codes inattendus : {sorted(set(codes))}"
    assert len({body["id"] for _, body in results}) == n, "identifiants en collision"

    _, inbox = _call(f"{server}/v1/messages?limit=200", None, receiver["chat_token"])
    assert inbox["count"] == n


def test_reading_while_writing_never_errors(server, peers):
    """Readers and writers at the same instant: the classic shape of a WAL
    contention bug."""
    sender, receiver = peers

    def write(i):
        return _call(f"{server}/v1/messages", {
            "to": "receiver", "subject": "mixte", "body": f"w{i}"},
            sender["chat_token"], "POST")[0]

    def read(_):
        return _call(f"{server}/v1/messages?limit=50", None, receiver["chat_token"])[0]

    with ThreadPoolExecutor(max_workers=10) as pool:
        writes = pool.map(write, range(20))
        reads = pool.map(read, range(20))
        codes = list(writes) + list(reads)

    assert set(codes) <= {200, 201}, f"codes inattendus : {sorted(set(codes))}"


def test_the_same_bytes_uploaded_at_once_stay_one_file(server, peers):
    """Content-addressed storage means concurrent uploads race for the same
    path. The rename is atomic, so the loser simply finds the file already
    there — but that is an assumption worth proving."""
    import base64
    sender, _ = peers
    payload = base64.b64encode(b"exactement les memes octets, en meme temps").decode()

    def upload(i):
        return _call(f"{server}/v1/blobs/inline", {
            "filename": f"copie-{i}.txt", "content_base64": payload},
            sender["chat_token"], "POST")

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(upload, range(6)))

    assert {code for code, _ in results} == {201}
    shas = {body["sha256"] for _, body in results}
    assert len(shas) == 1, "des octets identiques doivent donner une seule empreinte"
    assert len({body["blob_id"] for _, body in results}) == 6


def test_the_mcp_path_holds_up_too(server, peers):
    """The load test above hit /v1, but every real client goes through /mcp.
    That endpoint is async and calls synchronous database code, so it runs the
    work inside the event loop — the shape that stalls everything at once."""
    sender, receiver = peers
    n = 30

    def call(i):
        return _call(f"{server}/mcp", {
            "jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "send", "arguments": {
                "to": "receiver", "subject": f"mcp {i}", "body": f"charge {i}"}}},
            sender["chat_token"], "POST")

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(call, range(n)))
    elapsed = time.monotonic() - started

    assert {code for code, _ in results} == {200}
    errors = [body for _, body in results if body.get("result", {}).get("isError")]
    assert not errors, f"appels en erreur : {errors[:2]}"
    assert elapsed < 20, f"{n} appels MCP ont pris {elapsed:.1f}s — la boucle est bloquée"


def test_health_stays_responsive_while_a_long_poll_waits(server, peers):
    """A waiting long-poll must not hold the event loop hostage: if it does,
    every other caller waits with it — including a health check that decides
    whether the container is alive."""
    _, receiver = peers

    def long_poll():
        return _call(f"{server}/v1/events?since=0&timeout=3", None, receiver["chat_token"])[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        waiting = pool.submit(long_poll)
        time.sleep(0.3)
        started = time.monotonic()
        code, _ = _call(f"{server}/healthz")
        answered_in = time.monotonic() - started
        waiting.result()

    assert code == 200
    assert answered_in < 1.0, f"/healthz a mis {answered_in:.2f}s pendant un long-poll"


def test_a_large_attachment_over_mcp_does_not_stall_everyone(server, peers):
    """The one case where synchronous work inside the event loop really bites:
    attach_file decodes and writes up to a megabyte per call."""
    import base64
    sender, _ = peers
    payload = base64.b64encode(b"z" * 700_000).decode()

    def attach(i):
        return _call(f"{server}/mcp", {
            "jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "attach_file", "arguments": {
                "filename": f"gros-{i}.bin", "content_base64": payload}}},
            sender["chat_token"], "POST")[0]

    with ThreadPoolExecutor(max_workers=4) as pool:
        uploading = [pool.submit(attach, i) for i in range(3)]
        time.sleep(0.05)
        started = time.monotonic()
        code, _ = _call(f"{server}/healthz")
        answered_in = time.monotonic() - started
        assert all(f.result() == 200 for f in uploading)

    assert code == 200
    assert answered_in < 1.0, f"/healthz a mis {answered_in:.2f}s pendant des téléversements"
