"""Vault format v2: header key check, header and service binding, KDF limits,
v1 migration, and atomic private writes."""

import base64
import json
import os

import pytest

from vaultkeep import vault as vault_module
from vaultkeep.crypto import encrypt
from vaultkeep.kdf import derive_key
from vaultkeep.models import KDFParameters, VaultEntry, VaultFile, VaultHeader
from vaultkeep.vault import load_vault, save_vault

PASSWORD = b"Test123"


def b64(data):
    return base64.b64encode(data).decode("utf-8")


def new_vault(entries=()):
    vault = VaultFile(header=VaultHeader(vault_id=b"V" * 16, kdf_params=KDFParameters(salt=b"S" * 16)))
    for i, (service, username, password) in enumerate(entries):
        vault.entries.append(VaultEntry(item_id=bytes([i]) * 16, service=service, username=username, password=password))
    return vault


def saved(tmp_path, entries=()):
    path = str(tmp_path / "vault.json")
    save_vault(new_vault(entries), PASSWORD, path)
    return path


def edit(path, change):
    """Load the raw JSON, apply change(data), write it back - simulates an attacker editing the file."""
    with open(path) as f:
        data = json.load(f)
    change(data)
    with open(path, "w") as f:
        json.dump(data, f)


# --- password check works even with nothing to decrypt ---

def test_empty_vault_rejects_wrong_password(tmp_path):
    path = saved(tmp_path)
    with pytest.raises(ValueError, match="Wrong master password"):
        load_vault(b"WrongPass", path)


def test_empty_vault_accepts_right_password(tmp_path):
    path = saved(tmp_path)
    assert load_vault(PASSWORD, path).entries == []


# --- header and service names are authenticated ---

def test_changed_vault_id_is_detected(tmp_path):
    path = saved(tmp_path, [("gmail", "luis", "pw")])
    edit(path, lambda d: d["header"].__setitem__("vault_id", b64(b"X" * 16)))
    with pytest.raises(ValueError, match="Wrong master password"):
        load_vault(PASSWORD, path)


def test_swapped_service_names_are_detected(tmp_path):
    path = saved(tmp_path, [("gmail", "luis", "pw1"), ("github", "luis", "pw2")])

    def swap(d):
        a, b = d["entries"]
        a["service"], b["service"] = b["service"], a["service"]

    edit(path, swap)
    with pytest.raises(ValueError, match="Wrong master password"):
        load_vault(PASSWORD, path)


def test_absurd_kdf_cost_is_rejected_before_deriving(tmp_path):
    # A tampered header asking for 2 TiB of memory must fail fast, not hang the machine
    path = saved(tmp_path)
    edit(path, lambda d: d["header"]["kdf_params"].__setitem__("memory_cost", 2**31))
    with pytest.raises(ValueError, match="memory_cost"):
        load_vault(PASSWORD, path)


def test_unknown_cipher_is_rejected(tmp_path):
    path = saved(tmp_path)
    edit(path, lambda d: d["header"].__setitem__("cipher", "rot13"))
    with pytest.raises(ValueError, match="Unsupported cipher"):
        load_vault(PASSWORD, path)


def test_malformed_file_is_a_value_error(tmp_path):
    path = saved(tmp_path)
    edit(path, lambda d: d["header"].__setitem__("vault_id", "not base64!"))
    with pytest.raises(ValueError, match="malformed"):
        load_vault(PASSWORD, path)


# --- v1 vaults keep working and get upgraded ---

def write_v1_vault(path, entries):
    """Build a vault exactly the way format v1 did: no key check, AAD = vault_id || item_id."""
    params = KDFParameters(salt=b"S" * 16)
    vault_id = b"V" * 16
    key = derive_key(PASSWORD, params)
    data = {
        "header": {
            "magic": b64(b"VKEP"), "version": 1, "cipher": "aes-256-gcm",
            "vault_id": b64(vault_id), "wrapped_data_key": "",
            "kdf_params": {"algorithm": "argon2id", "salt": b64(params.salt), "time_cost": 3,
                           "memory_cost": 65536, "parallelism": 4},
        },
        "entries": [],
    }
    for i, (service, username, password) in enumerate(entries):
        item_id = bytes([i]) * 16
        payload = json.dumps({"username": username, "password": password, "notes": None}).encode()
        nonce, ct = encrypt(key, payload, vault_id + item_id)
        data["entries"].append({"item_id": b64(item_id), "service": service, "nonce": b64(nonce), "ciphertext": b64(ct)})
    with open(path, "w") as f:
        json.dump(data, f)


def test_v1_vault_loads_and_upgrades_on_save(tmp_path):
    path = str(tmp_path / "vault.json")
    write_v1_vault(path, [("gmail", "luis", "SuperSecret")])

    vault = load_vault(PASSWORD, path)
    assert vault.entries[0].password == "SuperSecret"

    save_vault(vault, PASSWORD, path)
    with open(path) as f:
        assert json.load(f)["header"]["version"] == 2
    assert load_vault(PASSWORD, path).entries[0].password == "SuperSecret"


def test_v1_vault_wrong_password_still_fails(tmp_path):
    path = str(tmp_path / "vault.json")
    write_v1_vault(path, [("gmail", "luis", "SuperSecret")])
    with pytest.raises(ValueError):
        load_vault(b"WrongPass", path)


def test_empty_v1_vault_is_refused(tmp_path):
    path = str(tmp_path / "vault.json")
    write_v1_vault(path, [])
    with pytest.raises(ValueError, match="init"):
        load_vault(PASSWORD, path)


# --- writes are atomic and private ---

def test_save_leaves_no_temp_files(tmp_path):
    saved(tmp_path, [("gmail", "luis", "pw")])
    assert sorted(os.listdir(tmp_path)) == ["vault.json"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_vault_file_is_owner_only(tmp_path):
    path = saved(tmp_path)
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_failed_save_keeps_the_old_vault(tmp_path, monkeypatch):
    path = saved(tmp_path, [("gmail", "luis", "pw")])
    with open(path) as f:
        before = f.read()

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(vault_module.json, "dump", boom)
    with pytest.raises(OSError):
        save_vault(new_vault([("github", "luis", "x")]), PASSWORD, path)

    with open(path) as f:
        assert f.read() == before
    assert sorted(os.listdir(tmp_path)) == ["vault.json"]
