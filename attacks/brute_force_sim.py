"""Brute force attack simulation for VaultKeep."""

import time
import sys, os
from vaultkeep.kdf import derive_key
from vaultkeep.vault import load_vault

# Note: Test123 appears early in this demo list.
# Real attackers use wordlists with millions of entries (e.g. rockyou.txt).
# At ~0.05s per guess, 14M passwords = ~8 days of compute time.
# SHA-256 would take milliseconds for the same attack.
COMMON_PASSWORDS = [
    "password",
    "qwerty",
    "letmein",
    "admin",
    "welcome",
    "monkey",
    "Test123",
    "abc123",
    "password1",
    "1234",
]


def brute_force(vault_path):
    """Simulate a brute force attack on the vault by trying common passwords."""

    print(f"Starting brute force attack on {vault_path}")
    print(f"Trying {len(COMMON_PASSWORDS)} common passwords...\n")

    for password in COMMON_PASSWORDS:
        start = time.time()
        try:
            load_vault(password.encode("utf-8"), vault_path)
            elapsed = time.time() - start
            print(f"[FOUND] Password: '{password}' — took {elapsed:.2f}s")
            return password
        except Exception:
            elapsed = time.time() - start
            print(f"[FAIL] '{password}' — took {elapsed:.2f}s")

    print("\nPassword not found in common password list.")
    return None


if __name__ == "__main__":
    # Entry point - takes vault path as command line argument

    if len(sys.argv) != 2:
        print("Usage: python brute_force_sim.py <vault_path>")
        sys.exit(1)

    vault_path = sys.argv[1]

    if not os.path.isfile(vault_path):
        print(f"Error: Vault file '{vault_path}' does not exist.")
        sys.exit(1)

    brute_force(vault_path)
