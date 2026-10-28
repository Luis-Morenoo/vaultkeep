"""Authentication and authorization utilities for the vaultkeep web interface"""

import os
import datetime
import jwt

MIN_SECRET_KEY_BYTES = 32  # HS256 needs a key at least as long as its 256-bit output
TOKEN_LIFETIME = datetime.timedelta(minutes=15)


def get_secret_key() -> str:
    """Read the JWT signing key from the environment and fail closed if it's missing or weak.
    There is deliberately no fallback: a default key would be public, so anyone could forge tokens."""
    key = os.environ.get("VAULTKEEP_SECRET_KEY", "")
    if len(key.encode("utf-8")) < MIN_SECRET_KEY_BYTES:
        raise RuntimeError(
            "VAULTKEEP_SECRET_KEY must be set to at least 32 bytes. Generate one with: "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return key


def generate_token(vault_id: bytes) -> str:
    """Generate a short-lived JWT bound to this vault's ID"""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "vault_id": vault_id.hex(),
        "iat": now,
        "exp": now + TOKEN_LIFETIME,
    }
    return jwt.encode(payload, get_secret_key(), algorithm="HS256")


def verify_token(token: str) -> dict:
    """Verify the signature and expiry, and require every claim we rely on"""
    try:
        return jwt.decode(
            token,
            get_secret_key(),
            algorithms=["HS256"],  # pinned: never let the token choose its own algorithm
            options={"require": ["exp", "iat", "vault_id"]},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
