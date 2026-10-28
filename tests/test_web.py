"""Web layer: fail-closed signing key, security headers, auth flow, token binding, rate limits."""

import pytest

from vaultkeep.models import KDFParameters, VaultFile, VaultHeader
from vaultkeep.vault import save_vault
from vaultkeep.web import routes
from vaultkeep.web.app import create_app
from vaultkeep.web.auth import generate_token
from vaultkeep.web.limiter import limiter

KEY = "k" * 64
PASSWORD = "Test123"


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTKEEP_SECRET_KEY", KEY)
    path = str(tmp_path / "vault.json")
    monkeypatch.setattr(routes, "VAULT_PATH", path)
    header = VaultHeader(vault_id=b"V" * 16, kdf_params=KDFParameters(salt=b"S" * 16))
    save_vault(VaultFile(header=header), PASSWORD.encode(), path)

    def factory(rate_limits=False):
        app = create_app({"TESTING": True, "RATELIMIT_ENABLED": rate_limits})
        return app.test_client()

    return factory


@pytest.fixture
def client(make_client):
    return make_client()


def login(client, password=PASSWORD):
    return client.post("/auth/login", json={"password": password})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# --- the app refuses to run with a missing or weak signing key ---

def test_app_refuses_to_start_without_key(monkeypatch):
    monkeypatch.delenv("VAULTKEEP_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app()


def test_app_refuses_short_key(monkeypatch):
    monkeypatch.setenv("VAULTKEEP_SECRET_KEY", "too-short")
    with pytest.raises(RuntimeError):
        create_app()


# --- browser hardening ---

def test_pages_send_security_headers_and_no_inline_script(client):
    response = client.get("/")
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    body = response.get_data(as_text=True)
    assert "/static/login.js" in body and "<script>" not in body


# --- auth flow ---

def test_login_rejects_wrong_password_on_empty_vault(client):
    assert login(client, "WrongPass").status_code == 401


def test_full_entry_flow(client):
    token = login(client).get_json()["token"]
    body = {"password": PASSWORD, "service": "gmail", "username": "luis", "entry_password": "pw"}

    assert client.post("/vault/entries", json=body, headers=auth(token)).status_code == 201
    assert client.post("/vault/entries", json=body, headers=auth(token)).status_code == 409

    listed = client.post("/vault/entries/list", json={"password": PASSWORD}, headers=auth(token))
    assert listed.get_json() == {"entries": [{"service": "gmail", "username": "luis"}]}

    deleted = client.delete("/vault/entries/gmail", json={"password": PASSWORD}, headers=auth(token))
    assert deleted.status_code == 200


def test_missing_or_malformed_bearer_is_rejected(client):
    assert client.post("/vault/entries/list", json={"password": PASSWORD}).status_code == 401
    bad = {"Authorization": "Token abc"}
    assert client.post("/vault/entries/list", json={"password": PASSWORD}, headers=bad).status_code == 401


def test_token_for_another_vault_is_rejected(client):
    other = generate_token(b"X" * 16)  # validly signed, but for a different vault_id
    response = client.post("/vault/entries/list", json={"password": PASSWORD}, headers=auth(other))
    assert response.status_code == 401


# --- rate limiting ---

def test_login_is_rate_limited(make_client):
    client = make_client(rate_limits=True)
    limiter.reset()
    codes = [login(client, "WrongPass").status_code for _ in range(6)]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429
    assert "error" in login(client, "WrongPass").get_json()
