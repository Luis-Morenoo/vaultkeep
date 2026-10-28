from vaultkeep.kdf import derive_key, verify_password
from vaultkeep.models import KDFParameters

PARAMS = KDFParameters(salt=b"S" * 16)


def test_derive_key_is_32_bytes():
    key = derive_key(b"Test123", PARAMS)
    assert len(key) == 32


def test_same_password_same_key():
    first = derive_key(b"Test123", PARAMS)
    second = derive_key(b"Test123", PARAMS)
    assert first == second


def test_correct_password_verifies():
    key = derive_key(b"Test123", PARAMS)
    assert verify_password(b"Test123", key, PARAMS) is True


def test_wrong_password_fails_verification():
    key = derive_key(b"Test123", PARAMS)
    assert verify_password(b"WrongPass", key, PARAMS) is False
