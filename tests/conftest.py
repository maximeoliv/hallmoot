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
        return TestClient(app)
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
