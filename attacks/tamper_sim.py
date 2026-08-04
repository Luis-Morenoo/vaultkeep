"""Tamper attack simulation for VaultKeep."""

import json
import os
import sys
import shutil
from vaultkeep.vault import load_vault

def tamper_sim(vault_path, tampered_vault_path, password):
    """Simulate a tamper attack by modifying the vault file."""

    # Backup/restore the original vault file to avoid data loss
    shutil.copy(vault_path, vault_path + ".backup")    

    # Load the original vault to get its structure
    with open(vault_path, 'r') as f:
        vault_data = json.load(f)

    # Tamper with the vault data (e.g., change a password)
    if 'entries' in vault_data and len(vault_data['entries']) > 0:
        original = vault_data['entries'][0]['ciphertext']
        vault_data['entries'][0]['ciphertext'] = original[:-4] + "AAAA"
        print(f"Original ciphertext: {original[:20]}...")
        print(f"Tampered ciphertext: AAAAAAA...")  

    # Save the tampered vault to a new file
    with open(tampered_vault_path, 'w') as f:
        json.dump(vault_data, f)

    print(f"Tampered vault saved to {tampered_vault_path}")

    # Attempt to load the tampered vault
    try:
        load_vault(password.encode("utf-8"), tampered_vault_path)
        print("Tampered vault loaded successfully (unexpected).")
    except Exception as e:
        print(f"Failed to load tampered vault as expected: {e}")

    shutil.copy(vault_path + ".backup", vault_path)
    os.remove(vault_path + ".backup")
    print("Original vault restored.")

if __name__ == "__main__":
    # Entry point - takes vault path, tampered vault path, and password as command line arguments

    if len(sys.argv) != 4:
        print("Usage: python tamper_sim.py <vault_path> <tampered_vault_path> <password>")
        sys.exit(1)

    vault_path = sys.argv[1]
    tampered_vault_path = sys.argv[2]
    password = sys.argv[3]

    if not os.path.isfile(vault_path):
        print(f"Error: Vault file '{vault_path}' does not exist.")
        sys.exit(1)

    tamper_sim(vault_path, tampered_vault_path, password)
