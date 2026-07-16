""" Vault handles reading and writing encrypted vault files to disk."""

import json
import os
import base64
from .models import VaultHeader, VaultEntry, VaultFile, AuditLogEntry, KDFParameters
from .kdf import derive_key
from .crypto import encrypt, decrypt

def save_vault(vault: VaultFile, password: bytes, path: str) -> None:
    """ Save the given vault to disk at the specified path, encrypting the entries with a key derived from the password. 
    The vault header is stored in plaintext at the beginning of the file, while the entries are stored encrypted in the 
    vault data following the header. """

    # Derive the KEK from the password and KDF parameters in the vault header
    kek = derive_key(password, vault.header.kdf_params)

    # Build a dictionary representing the vault as JSON-serializable data
    vault_dict = {
        "header": {
            "magic": base64.b64encode(vault.header.magic).decode('utf-8'),
            "version": vault.header.version,
            "cipher": vault.header.cipher,
            "vault_id": base64.b64encode(vault.header.vault_id).decode('utf-8'),
            "wrapped_data_key": base64.b64encode(vault.header.wrapped_data_key).decode('utf-8'),
            "kdf_params": {
                "algorithm": vault.header.kdf_params.algorithm,
                "salt": base64.b64encode(vault.header.kdf_params.salt).decode('utf-8'),
                "time_cost": vault.header.kdf_params.time_cost,
                "memory_cost": vault.header.kdf_params.memory_cost,
                "parallelism": vault.header.kdf_params.parallelism
            }
        },
        "entries": [] 
    }
    
    for entry in vault.entries:
        # Use the vault_id and entry_id as associated data to ensure the encrypted data is tied to this specific vault and entry
        aad = vault.header.vault_id + entry.item_id

        # Build the plaintext payload for this entry, which includes the username, password, and optional notes, and encrypt it with the KEK and associated data
        payload = {
            "username" : entry.username,
            "password" : entry.password,
            "notes" : entry.notes,
        }

        # serializing the payload dict to bytes so it can be encrypted - we use JSON for simplicity and readability, but other formats could be used as well
        plaintext = json.dumps(payload).encode('utf-8')
        # The encrypt function returns a tuple of (nonce, ciphertext), which allows the nonce to be stored alongside the encrypted data for later decryption
        nonce, ciphertext = encrypt(kek, plaintext, aad)

        # Append the encrypted entry data to the vault dictionary, encoding the item_id, nonce, and ciphertext as base64 strings for JSON serialization
        vault_dict["entries"].append({
            "item_id" : base64.b64encode(entry.item_id).decode('utf-8'),
            "service" : entry.service,
            "nonce" : base64.b64encode(nonce).decode('utf-8'),
            "ciphertext" : base64.b64encode(ciphertext).decode('utf-8'),
        })

    # Write the vault dictionary as JSON to the specified file path, with indentation for readability
    with open(path, "w") as f:
        json.dump(vault_dict, f, indent=2)
    
def load_vault(password: bytes, path: str) -> VaultFile:
    """ Load the vault from disk at the specified path, decrypting the entries with a key derived from the password. 
    The vault header is read from the beginning of the file, while the entries are read from the vault data following the header. """

    # Read the Json from disk
    with open(path, "r") as f:
        data = json.load(f)

    # Reconstruct KDFParamaters from the JSON - we need this to derive the KEK before we can reconstruct the VaultHeader, which contains the KDF parameters in its header field
    kdf_params = KDFParameters(
        algorithm = data["header"]["kdf_params"]["algorithm"],
        salt = base64.b64decode(data["header"]["kdf_params"]["salt"]), 
        time_cost = data["header"]["kdf_params"]["time_cost"],
        memory_cost = data["header"]["kdf_params"]["memory_cost"],
        parallelism = data["header"]["kdf_params"]["parallelism"]
    )

    # Reconstruct VaultHeader from the JSON - we need this to derive the KEK before we can reconstruct the VaultFile, which contains the header field
    vault_header = VaultHeader(
        magic = base64.b64decode(data["header"]["magic"]),
        version = data["header"]["version"],
        kdf_params = kdf_params,
        cipher = data["header"]["cipher"],
        vault_id = base64.b64decode(data["header"]["vault_id"]),
        wrapped_data_key = base64.b64decode(data["header"]["wrapped_data_key"])
    )

    # Derive the KEK from the password and KDF parameters in the vault header - we need this to decrypt the entries before we can reconstruct the VaultFile, which contains the list of entries
    kek = derive_key(password, vault_header.kdf_params)

    # Reconstruct the list of VaultEntry objects from the JSON, decrypting each entry's ciphertext with the KEK and associated data (vault_id + item_id) - we need this to reconstruct the VaultFile, which contains the list of entries
    entries = []
    # We loop through each entry in the JSON data, decode the item_id, nonce, and ciphertext from base64, construct the associated data by concatenating the vault_id and item_id, decrypt the ciphertext to get the plaintext payload, parse the payload as JSON to extract the username, password, and notes, and then create a VaultEntry object with this data and append it to the list of entries.
    for entry_data in data["entries"]:
        item_id = base64.b64decode(entry_data["item_id"])
        nonce = base64.b64decode(entry_data["nonce"])
        ciphertext = base64.b64decode(entry_data["ciphertext"])
        aad = vault_header.vault_id + item_id
        plaintext = decrypt(kek, nonce, ciphertext, aad)
        payload = json.loads(plaintext.decode('utf-8'))
        entry = VaultEntry(
            item_id = item_id,
            service = entry_data["service"],
            username = payload["username"],
            password = payload["password"],
            notes = payload.get("notes")
        )
        entries.append(entry)
        
    # Finally, we return a VaultFile object containing the reconstructed header and list of entries
    return VaultFile(header=vault_header, entries=entries)

