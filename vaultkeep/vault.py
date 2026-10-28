"""Vault handles reading and writing encrypted vault files to disk.

Format v2 (current):
  * The header is authenticated. A fixed key-check value is encrypted with the
    vault key, using the canonical header as associated data. Unlocking checks it
    first, so a wrong password fails even for an empty vault, and changing any
    header field (vault_id, KDF settings, cipher, version) is detected.
  * Each entry's associated data is vault_id || item_id || service, so service
    names can't be swapped between entries without decryption failing.
Format v1 (legacy) is still readable and is upgraded to v2 on the next save.
"""

import base64
import binascii
import hmac
import json
import os
import tempfile

from .models import VaultHeader, VaultEntry, VaultFile, KDFParameters
from .kdf import derive_key
from .crypto import encrypt, decrypt

MAGIC = b"VKEP"
CURRENT_VERSION = 2
SUPPORTED_VERSIONS = (1, 2)
SUPPORTED_CIPHER = "aes-256-gcm"
KEY_CHECK_PLAINTEXT = b"vaultkeep-key-check-v2"

WRONG_PASSWORD = "Wrong master password, or the vault file has been modified"  # nosec B105 - user-facing error text, not a credential


# ---------- encoding helpers ----------

def _b64(data: bytes) -> str:
    """Encode bytes as a base64 string for JSON."""
    return base64.b64encode(data).decode("utf-8")


def _unb64(text: str) -> bytes:
    """Decode a base64 string, rejecting anything that isn't strictly valid base64."""
    return base64.b64decode(text, validate=True)


# ---------- associated data (what each GCM tag protects besides the ciphertext) ----------

def _header_aad(header: VaultHeader) -> bytes:
    """Canonical bytes of every header field except the key check itself.
    sort_keys + fixed separators make the encoding identical on every save and load."""
    fields = {
        "magic": _b64(header.magic),
        "version": header.version,
        "cipher": header.cipher,
        "vault_id": _b64(header.vault_id),
        "wrapped_data_key": _b64(header.wrapped_data_key),
        "kdf_params": {
            "algorithm": header.kdf_params.algorithm,
            "salt": _b64(header.kdf_params.salt),
            "time_cost": header.kdf_params.time_cost,
            "memory_cost": header.kdf_params.memory_cost,
            "parallelism": header.kdf_params.parallelism,
        },
    }
    return b"VKEP-header-v2|" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_aad(version: int, vault_id: bytes, item_id: bytes, service: str) -> bytes:
    """v2 binds the service name; v1 only bound vault_id and item_id.
    vault_id and item_id are fixed 16 bytes, so appending the service is unambiguous."""
    if version >= 2:
        return b"VKEP-entry-v2|" + vault_id + item_id + service.encode("utf-8")
    return vault_id + item_id


# ---------- save ----------

def save_vault(vault: VaultFile, password: bytes, path: str) -> None:
    """Encrypt the vault with a key derived from the password and write it to disk.
    Always writes the current format (v2), which upgrades v1 vaults automatically."""

    header = vault.header
    header.version = CURRENT_VERSION

    # Derive the vault key from the password (derive_key also validates the KDF settings)
    kek = derive_key(password, header.kdf_params)

    # Fresh key check every save: encrypt a known value with the whole header as associated data
    header.key_check_nonce, header.key_check = encrypt(kek, KEY_CHECK_PLAINTEXT, _header_aad(header))

    vault_dict = {
        "header": {
            "magic": _b64(header.magic),
            "version": header.version,
            "cipher": header.cipher,
            "vault_id": _b64(header.vault_id),
            "wrapped_data_key": _b64(header.wrapped_data_key),
            "kdf_params": {
                "algorithm": header.kdf_params.algorithm,
                "salt": _b64(header.kdf_params.salt),
                "time_cost": header.kdf_params.time_cost,
                "memory_cost": header.kdf_params.memory_cost,
                "parallelism": header.kdf_params.parallelism,
            },
            "key_check_nonce": _b64(header.key_check_nonce),
            "key_check": _b64(header.key_check),
        },
        "entries": [],
    }

    for entry in vault.entries:
        # Username, password and notes are encrypted together as one payload
        payload = {"username": entry.username, "password": entry.password, "notes": entry.notes}
        plaintext = json.dumps(payload).encode("utf-8")
        aad = _entry_aad(header.version, header.vault_id, entry.item_id, entry.service)
        nonce, ciphertext = encrypt(kek, plaintext, aad)
        vault_dict["entries"].append({
            "item_id": _b64(entry.item_id),
            "service": entry.service,
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        })

    _atomic_write_json(path, vault_dict)


def _atomic_write_json(path: str, data: dict) -> None:
    """Write to a private temp file in the same folder, then swap it into place.
    A crash mid-write leaves the old vault intact instead of a half-written one."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=directory)  # created with 0600 on POSIX
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)  # atomic on the same file system
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


# ---------- load ----------

def load_vault(password: bytes, path: str) -> VaultFile:
    """Read the vault from disk, verify the password and integrity, and decrypt every entry.
    Raises ValueError for a wrong password, a modified file, or a malformed file."""

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)  # JSONDecodeError is a ValueError

    try:
        header, raw_entries = _parse(data)
    except (KeyError, TypeError, binascii.Error) as exc:
        raise ValueError("Vault file is malformed") from exc

    # Derive the key (derive_key rejects unsafe or absurd KDF settings before doing any work)
    kek = derive_key(password, header.kdf_params)

    if header.version >= 2:
        # Verify the password and every header field before touching any entry
        try:
            check = decrypt(kek, header.key_check_nonce, header.key_check, _header_aad(header))
        except ValueError:
            raise ValueError(WRONG_PASSWORD) from None
        if not hmac.compare_digest(check, KEY_CHECK_PLAINTEXT):
            raise ValueError(WRONG_PASSWORD)
    elif not raw_entries:
        # A v1 vault with no entries has nothing to decrypt, so the password can't be checked
        raise ValueError(
            "This vault uses the old v1 format and has no entries, so the master password "
            "can't be verified. Delete it and run 'init' again."
        )

    entries = []
    for item_id, service, nonce, ciphertext in raw_entries:
        aad = _entry_aad(header.version, header.vault_id, item_id, service)
        try:
            plaintext = decrypt(kek, nonce, ciphertext, aad)
        except ValueError:
            raise ValueError(WRONG_PASSWORD) from None
        payload = json.loads(plaintext.decode("utf-8"))
        entries.append(VaultEntry(
            item_id=item_id,
            service=service,
            username=payload["username"],
            password=payload["password"],
            notes=payload.get("notes"),
        ))

    return VaultFile(header=header, entries=entries)


def _parse(data: dict):
    """Turn the JSON dictionary into a VaultHeader plus raw (still encrypted) entries,
    checking the fixed fields so unknown formats fail early with a clear message."""
    h = data["header"]

    magic = _unb64(h["magic"])
    if magic != MAGIC:
        raise ValueError("Not a VaultKeep vault file")
    version = h["version"]
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported vault version: {version}")
    if h["cipher"] != SUPPORTED_CIPHER:
        raise ValueError(f"Unsupported cipher: {h['cipher']}")

    k = h["kdf_params"]
    kdf_params = KDFParameters(
        algorithm=k["algorithm"],
        salt=_unb64(k["salt"]),
        time_cost=k["time_cost"],
        memory_cost=k["memory_cost"],
        parallelism=k["parallelism"],
    )

    header = VaultHeader(
        magic=magic,
        version=version,
        kdf_params=kdf_params,
        cipher=h["cipher"],
        vault_id=_unb64(h["vault_id"]),
        wrapped_data_key=_unb64(h.get("wrapped_data_key", "")),
        key_check_nonce=_unb64(h["key_check_nonce"]) if version >= 2 else b"",
        key_check=_unb64(h["key_check"]) if version >= 2 else b"",
    )
    if len(header.vault_id) != 16:
        raise ValueError("Vault file is malformed")

    raw_entries = []
    for e in data["entries"]:
        item_id = _unb64(e["item_id"])
        if len(item_id) != 16 or not isinstance(e["service"], str):
            raise ValueError("Vault file is malformed")
        raw_entries.append((item_id, e["service"], _unb64(e["nonce"]), _unb64(e["ciphertext"])))
    return header, raw_entries
