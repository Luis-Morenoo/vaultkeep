"""Contains all API endpoints"""

from flask import Blueprint, request, jsonify, render_template
from .auth import generate_token, verify_token
from .limiter import limiter
from ..vault import load_vault, save_vault
from ..models import VaultEntry
from ..utils import generate_random_bytes
import os
import functools

vault_bp = Blueprint("vault", __name__)

VAULT_PATH = os.path.expanduser("~/.vaultkeep/vault.json")


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # code that runs BEFORE the wrapped function
        # if checks pass, call the original function
        # get the token from the request header
        auth_header = request.headers.get("Authorization", "")

        # split the header and grap the second part
        token = auth_header.split(" ")[-1]

        try:
            payload = verify_token(token)
            return f(payload, *args, **kwargs)
        except ValueError:
            return jsonify({"error": "Unauthorized"}), 401

    return decorated


@vault_bp.route("/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # Get json data and validate password exists
    data = request.get_json()
    if not data or "password" not in data:
        return jsonify({"error": "Password required"}), 400
    try:
        # try to load vault
        password = data["password"]
        vault = load_vault(password.encode("utf-8"), VAULT_PATH)

        # generate token
        token = generate_token(vault.header.vault_id)
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"token": token})


@vault_bp.route("/vault/entries/list", methods=["POST"])
@require_auth
def get_entries(payload):
    # get master password from request JSON
    data = request.get_json()
    if not data or "password" not in data:
        return jsonify({"error": "Password required"}), 400
    # load vault
    password = data["password"]

    try:
        vault = load_vault(password.encode("utf-8"), VAULT_PATH)
    except ValueError:
        return jsonify({"error": "Invalid password"}), 401

    return jsonify(
        {
            "entries": [
                {"service": e.service, "username": e.username} for e in vault.entries
            ]
        }
    )


@vault_bp.route("/vault/entries", methods=["POST"])
@require_auth
def add_entries(payload):
    # get password, service, username, entry_password from request JSON
    data = request.get_json()
    if not data or not all(
        k in data for k in ["password", "service", "username", "entry_password"]
    ):
        return (
            jsonify(
                {"error": "Password, service, username, and entry_password required"}
            ),
            400,
        )

    # load vault
    password = data["password"]
    service = data["service"]
    username = data["username"]
    entry_password = data["entry_password"]

    try:
        vault = load_vault(password.encode("utf-8"), VAULT_PATH)
    except ValueError:
        return jsonify({"error": "Invalid password"}), 401

    # entries are unique on (service, username) - one service can hold many accounts
    if any(e.service == service and e.username == username for e in vault.entries):
        return jsonify({"error": f"Entry for {username} on {service} already exists"}), 409

    # create vault entry
    entry = VaultEntry(
        item_id=generate_random_bytes(16),
        service=service,
        username=username,
        password=entry_password,
    )

    # append
    vault.entries.append(entry)
    # save
    save_vault(vault, password.encode("utf-8"), VAULT_PATH)
    # return
    return jsonify({"message": "Entry created successfully"}), 201


@vault_bp.route("/vault/entries/<service>", methods=["DELETE"])
@require_auth
def delete_entry(payload, service):
    # get and validate password from json
    data = request.get_json()
    if not data or "password" not in data:
        return jsonify({"error": "Password required"}), 400

    # load vault
    password = data["password"]

    try:
        vault = load_vault(password.encode("utf-8"), VAULT_PATH)
    except ValueError:
        return jsonify({"error": "Invalid password"}), 401

    # optional username narrows the match when a service has several accounts
    username = data.get("username")
    matches = [
        e
        for e in vault.entries
        if e.service == service and (username is None or e.username == username)
    ]

    if not matches:
        return jsonify({"error": "Entry not found"}), 404

    if username is None and len(matches) > 1:
        names = [e.username for e in matches]
        return (
            jsonify(
                {
                    "error": f"{service} has multiple accounts - include a username",
                    "usernames": names,
                }
            ),
            409,
        )

    vault.entries.remove(matches[0])
    save_vault(vault, password.encode("utf-8"), VAULT_PATH)
    return jsonify({"message": "Entry deleted successfully"}), 200


@vault_bp.route("/")
def index():
    return render_template("login.html")


@vault_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
