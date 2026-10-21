import pytest
from vaultkeep.vault import save_vault, load_vault
from vaultkeep.models import VaultFile, VaultHeader, VaultEntry, KDFParameters


def make_vault():
    header = VaultHeader(vault_id=b"V" * 16, kdf_params=KDFParameters(salt=b"S" * 16))
    vault = VaultFile(header=header)
    vault.entries.append(
        VaultEntry(item_id=b"I" * 16, service="gmail", username="luis@gmail.com", password="SuperSecret")
    )
    return vault


def test_save_load_roundtrip(tmp_path):
    path = str(tmp_path / "vault.json")
    save_vault(make_vault(), b"Test123", path)

    loaded = load_vault(b"Test123", path)
    assert loaded.entries[0].service == "gmail"
    assert loaded.entries[0].username == "luis@gmail.com"
    assert loaded.entries[0].password == "SuperSecret"


def test_wrong_master_password_fails(tmp_path):
    path = str(tmp_path / "vault.json")
    save_vault(make_vault(), b"Test123", path)

    with pytest.raises(ValueError):
        load_vault(b"WrongPass", path)