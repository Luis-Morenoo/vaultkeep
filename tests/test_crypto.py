import pytest
from vaultkeep.crypto import encrypt, decrypt


def test_encrypt_decrypt_roundtrip():
    # setup
    key = b"A" * 32  # 32 bytes = valid AES-256 key
    plaintext = b"hello vaultkeep"
    aad = b"test-aad"

    # encrypt then decrypt
    nonce, ciphertext = encrypt(key, plaintext, aad)
    result = decrypt(key, nonce, ciphertext, aad)

    assert result == plaintext


def test_wrong_key_fails():
    # setup
    key1 = b"A" * 32  # 32 bytes = valid AES-256 key
    key2 = b"B" * 32  # different key
    plaintext = b"hello vaultkeep"
    aad = b"test-aad"

    # encrypt with one key, decrypt with different key
    nonce, ciphertext = encrypt(key1, plaintext, aad)

    # assert raises ValueError
    with pytest.raises(ValueError):
        decrypt(key2, nonce, ciphertext, aad)


def test_tampered_ciphertext_fails():
    # setup
    key = b"A" * 32  # 32 bytes = valid AES-256 key
    plaintext = b"hello vaultkeep"
    aad = b"test-aad"

    # encrypt, modify ciphertext, try to decrypt
    nonce, ciphertext = encrypt(key, plaintext, aad)
    tampered_ciphertext = ciphertext[:-1] + b"\x00"  # modify last byte

    # assert raises ValueError
    with pytest.raises(ValueError):
        decrypt(key, nonce, tampered_ciphertext, aad)
