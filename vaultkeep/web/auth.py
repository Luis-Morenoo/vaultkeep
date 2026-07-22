"""Authentication and authorization utilities for the vaultkeep web interface"""

import os
import jwt
import datetime
from flask import request

SECRET_KEY = os.environ.get("VAULTKEEP_SECRET_KEY", "dev-secret-change-in-production")


def generate_token(vault_id: bytes) -> str:
    """Generate a JWT token for the given vault ID"""

    payload = {
        "vault_id": vault_id.hex(),
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=15),
    }

    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> dict:
    """Verify token"""

    # Handle exceptions
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
