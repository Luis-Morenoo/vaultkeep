"""Derive cryptographic keys from passwords using Argon2id, with parameters 
specified in the KDFParameters dataclass."""

from .models import KDFParameters
from argon2.low_level import hash_secret_raw, Type # type: ignore
import hmac

# -> bytes is used to indicate that this function promises to return a bytes object, which is the derived key
# Sanity limits for KDF settings read from a vault file. A tampered header could otherwise
# ask for absurd costs (e.g. terabytes of memory) and hang the machine before any check runs.
MIN_TIME_COST, MAX_TIME_COST = 1, 20
MIN_MEMORY_KIB, MAX_MEMORY_KIB = 8 * 1024, 1024 * 1024   # 8 MiB .. 1 GiB
MIN_PARALLELISM, MAX_PARALLELISM = 1, 16
MIN_SALT_BYTES, MAX_SALT_BYTES = 16, 64


def validate_params(params: KDFParameters) -> None:
    """Reject KDF settings outside sane bounds before spending any CPU or memory on them."""
    if params.algorithm != "argon2id":
        raise ValueError(f"Unsupported KDF algorithm: {params.algorithm}")
    for name, value, low, high in (
        ("time_cost", params.time_cost, MIN_TIME_COST, MAX_TIME_COST),
        ("memory_cost", params.memory_cost, MIN_MEMORY_KIB, MAX_MEMORY_KIB),
        ("parallelism", params.parallelism, MIN_PARALLELISM, MAX_PARALLELISM),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ValueError(f"KDF {name} must be an integer between {low} and {high}")
    if not params.salt:
        raise ValueError("Salt cannot be empty")
    if not MIN_SALT_BYTES <= len(params.salt) <= MAX_SALT_BYTES:
        raise ValueError(f"Salt must be between {MIN_SALT_BYTES} and {MAX_SALT_BYTES} bytes long")


def derive_key(password: bytes, params: KDFParameters) -> bytes:
    """Derive a cryptographic key from the given password and KDF parameters using Argon2id."""

    if not password:
        raise ValueError("Password cannot be empty")
    validate_params(params)

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


    