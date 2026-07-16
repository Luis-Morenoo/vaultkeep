""" Utility functions for the vaultkeep application """

import secrets
import hmac

def generate_random_bytes(n: int) -> bytes:
    """ Generate n random bytes using the secrets module, which is suitable for cryptographic use. """
    return secrets.token_bytes(n)

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """ Compare two byte strings in constant time to prevent timing attacks. """
    return hmac.compare_digest(a, b)

def build_aad(vault_id: bytes, entry_id: bytes) -> bytes:
    """ Build the associated data (AAD) for encryption/decryption by concatenating the vault_id and entry_id. 
    This ensures that the encrypted data is tied to the specific vault and entry, preventing cross-vault or 
    cross-entry decryption. """
    return vault_id + entry_id