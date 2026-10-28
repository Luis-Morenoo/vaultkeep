"""Contains all API endpoints"""

import functools
import os

from flask import Blueprint, request, jsonify, render_template
from .auth import generate_token, verify_token
from .limiter import limiter
from ..vault import load_vault, save_vault
from ..models import VaultEntry
from ..utils import generate_random_bytes

vault_bp = Blueprint("vault", __name__)

# Vault folder: ~/.vaultkeep by default, overridable with VAULTKEEP_HOME (same as the CLI)
VAULT_PATH = os.path.join(
    os.path.expanduser(os.environ.get("VAULTKEEP_HOME", "~/.vaultkeep")), "vault.json"
)

# Every route that accepts the master password is rate-limited, not just login
LOGIN_LIMIT = "5 per minute"
VAULT_LIMIT = "30 per minute"


def require_auth(f):
    """Reject the request unless it carries a valid, unexpired 'Bearer <token>' header"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        scheme, _, token = auth_header.partition(" ")
        if scheme != "Bearer" or not token:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            payload = verify_token(token)
        except ValueError:
            return jsonify({"error": "Unauthorized"}), 401
        return f(payload, *args, **kwargs)

    return decorated


def _open_vault(payload=None):
    """Read the master password from the JSON body and unlock the vault.
    Returns (data, password, vault, None) on success or (.., error_response) on failure.
    If a token payload is given, the token must belong to this exact vault."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("password"), str) or not data["password"]:
        return None, None, None, (jsonify({"error": "Password required"}), 400)
    password = data["password"]

    if not os.path.exists(VAULT_PATH):
        return None, None, None, (jsonify({"error": "No vault found. Run 'init' first."}), 404)
    try:
        vault = load_vault(password.encode("utf-8"), VAULT_PATH)
    except ValueError:
        return None, None, None, (jsonify({"error": "Invalid password"}), 401)

    # A token issued for a different (e.g. deleted and re-created) vault is not valid here
    if payload is not None and payload.get("vault_id") != vault.header.vault_id.hex():
        return None, None, None, (jsonify({"error": "Unauthorized"}), 401)
    return data, password, vault, None


@vault_bp.route("/auth/login", methods=["POST"])
@limiter.limit(LOGIN_LIMIT)
def login():
    _, _, vault, error = _open_vault()
    if error:
        # Same response for wrong password and missing body details, so nothing leaks
        return (jsonify({"error": "Unauthorized"}), 401) if error[1] == 401 else error
    return jsonify({"token": generate_token(vault.header.vault_id)})


@vault_bp.route("/vault/entries/list", methods=["POST"])
@limiter.limit(VAULT_LIMIT)
@require_auth
def get_entries(payload):
    _, _, vault, error = _open_vault(payload)
    if error:
        return error
    return jsonify(
        {"entries": [{"service": e.service, "username": e.username} for e in vault.entries]}
    )


@vault_bp.route("/vault/entries", methods=["POST"])
@limiter.limit(VAULT_LIMIT)
@require_auth
def add_entries(payload):
    data, password, vault, error = _open_vault(payload)
    if error:
        return error

    fields = ("service", "username", "entry_password")
    if not all(isinstance(data.get(k), str) and data[k] for k in fields):
        return jsonify({"error": "password, service, username, and entry_password are required"}), 400
    service, username, entry_password = (data[k] for k in fields)

    # Entries are unique on (service, username) - one service can hold many accounts
    if any(e.service == service and e.username == username for e in vault.entries):
        return jsonify({"error": f"Entry for {username} on {service} already exists"}), 409

    vault.entries.append(VaultEntry(
        item_id=generate_random_bytes(16),
        service=service,
        username=username,
        password=entry_password,
    ))
    save_vault(vault, password.encode("utf-8"), VAULT_PATH)
    return jsonify({"message": "Entry created successfully"}), 201


@vault_bp.route("/vault/entries/<service>", methods=["DELETE"])
@limiter.limit(VAULT_LIMIT)
@require_auth
def delete_entry(payload, service):
    data, password, vault, error = _open_vault(payload)
    if error:
        return error

    # Optional username narrows the match when a service has several accounts
    username = data.get("username")
    matches = [
        e for e in vault.entries
        if e.service == service and (username is None or e.username == username)
    ]
    if not matches:
        return jsonify({"error": "Entry not found"}), 404
    if username is None and len(matches) > 1:
        return jsonify({
            "error": f"{service} has multiple accounts - include a username",
            "usernames": [e.username for e in matches],
        }), 409

    vault.entries.remove(matches[0])
    save_vault(vault, password.encode("utf-8"), VAULT_PATH)
    return jsonify({"message": "Entry deleted successfully"}), 200


@vault_bp.route("/")
def index():
    return render_template("login.html")


@vault_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
