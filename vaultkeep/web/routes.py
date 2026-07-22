"""Contains all API endpoints"""

from flask import Blueprint, request, jsonify
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


@vault_bp.route("/vault/entries", methods=["GET"])
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

    return jsonify({"services": [entry.service for entry in vault.entries]})


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

    # loop through entries - find matching service, remove it, save, return 200
    for entry in vault.entries:
        if entry.service == service:
            vault.entries.remove(entry)
            save_vault(vault, password.encode("utf-8"), VAULT_PATH)
            return jsonify({"message": "Entry deleted successfully"}), 200
    else:
        return jsonify({"error": "Entry not found"}), 404

