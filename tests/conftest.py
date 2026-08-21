import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import create_app

OWNER = "test-owner-token"


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    """Build an isolated instance (its own SQLite file) per test."""
    def _make(rate_limit: int = 600, max_body: int | None = None):
        monkeypatch.setattr(config, "RATE_LIMIT_PER_MIN", rate_limit)
        if max_body is not None:
            monkeypatch.setattr(config, "MAX_BODY_BYTES", max_body)
        app = create_app(db_path=tmp_path / "test.sqlite3", owner_token=OWNER)
        # https, because a real browser reaches this server over https and the
        # sign-in cookie is marked Secure. A plain-http test client would drop
        # that cookie and hide a flow that works perfectly in production.
        return TestClient(app, base_url="https://testserver")
    return _make


@pytest.fixture
def client(make_client):
    return make_client()


def owner_headers():
    return {"Authorization": f"Bearer {OWNER}"}


def enroll(client, handle: str, display_name: str | None = None) -> dict:
    """Owner mints an invite, a chat trades it for its identity + token."""
    inv = client.post("/v1/admin/invites", json={"note": handle}, headers=owner_headers())
    assert inv.status_code == 201, inv.text
    res = client.post("/v1/register", json={
        "invite_code": inv.json()["invite_code"],
        "handle": handle,
        "display_name": display_name or handle,
        "client": "pytest",
    })
    assert res.status_code == 201, res.text
    data = res.json()
    data["headers"] = {"Authorization": f"Bearer {data['chat_token']}"}
    return data


@pytest.fixture
def alice(client):
    return enroll(client, "alice")


@pytest.fixture
def bob(client):
    return enroll(client, "bob")


@pytest.fixture
def mallory(client):
    return enroll(client, "mallory")

def pytest_runtest_logreport(report):
    """Turn a failure into a GitHub annotation.

    A run's logs need a token to read; its annotations do not. Without this, a
    suite that is green everywhere and red on the runner is a wall — you can see
    that it failed and not why, which is the least useful thing a CI can tell
    you. Annotations are public on a public repository, so the failure travels
    with the run.
    """
    import os
    if report.when != "call" or not report.failed or not os.environ.get("GITHUB_ACTIONS"):
        return
    where = str(report.location[0]), (report.location[1] or 0) + 1
    text = str(report.longrepr)
    # Annotations are one line: real newlines have to be escaped, and very long
    # tracebacks are cut from the front, where the assertion actually is.
    body = text[-3000:].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::error file={where[0]},line={where[1]},title={report.location[2]}::{body}")
