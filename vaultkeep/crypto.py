""" This module provides functions for encrypting and decrypting data using AES-GCM.
It uses the AESGCM class from the cryptography library to perform authenticated encryption and decryption.
The vault_id from the vault header is used as associated data to ensure that the encrypted data is tied to 
the specific vault and cannot be decrypted with a different vault_id, even if the same password is used.  """

from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore
from cryptography.exceptions import InvalidTag # type: ignore
import os

def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """ Encrypt the given plaintext using AES-GCM with the provided key and aad as associated data.
    A random 12-byte nonce is generated for each encryption operation, which is required for AES-GCM.
    The function returns a tuple of (nonce,ciphertext), which allows the nonce to be stored 
    alongside the encrypted data for later decryption. """

    # generate nonce - must be 12 bytes for AES-GCM
    nonce = os.urandom(12)

    # create AESGCM cipher object with the provided key
    aesgcm = AESGCM(key)

    # encrypt the plaintext with the nonce and associated data
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
 
    # return the nonce concatenated with the ciphertext so the nonce can be stored with the encrypted data for later decryption
    return  (nonce, ciphertext) 

def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """ Decrypt the given ciphertext using AES-GCM with the provided key, nonce, and aad as associated data.
    The function returns the decrypted plaintext if successful, or raises an exception if decryption fails 
    (e.g. due to an invalid key, corrupted data, or incorrect associated data). """

    # create AESGCM cipher object with the provided key
    aesgcm = AESGCM(key)

    try:
        # decrypt the ciphertext with the nonce and associated data - this will raise an exception if decryption fails (e.g. due to invalid key, corrupted data, or incorrect associated data)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise ValueError("Decryption failed: invalid key, corrupted data, or incorrect associated data")

    return plaintext


