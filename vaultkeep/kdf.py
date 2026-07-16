"""Derive cryptographic keys from passwords using Argon2id, with parameters 
specified in the KDFParameters dataclass."""

from .models import KDFParameters
from argon2.low_level import hash_secret_raw, Type # type: ignore
import hashlib
import hmac

# -> bytes is used to indicate that this function promises to return a bytes object, which is the derived key
def derive_key(password: bytes, params: KDFParameters) -> bytes:
    """Derive a cryptographic key from the given password and KDF parameters using Argon2id."""

    if not password:
        raise ValueError("Password cannot be empty")
    if not params.salt:
        raise ValueError("Salt cannot be empty")
    if len(params.salt) < 16:
        raise ValueError("Salt must be at least 16 bytes long")

    return hash_secret_raw(
        secret = password,
        salt = params.salt,
        time_cost = params.time_cost,
        memory_cost = params.memory_cost,
        parallelism = params.parallelism,
        hash_len = 32, # 32 bytes = 256 bits for AES-256
        type = Type.ID
    )

# -> bool indicates that this function returns a boolean value indicating whether the password is correct or not
def verify_password(password: bytes, stored_key: bytes, params: KDFParameters) -> bool:
    """Verify that the given password derives the same key as the stored key using the provided KDF parameters."""

    return hmac.compare_digest(derive_key(password, params), stored_key)


    