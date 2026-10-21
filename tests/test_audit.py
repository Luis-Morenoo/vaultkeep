from vaultkeep.audit import append_audit_log, get_last_hash

GENESIS = "0" * 64


def test_missing_log_returns_genesis_hash(tmp_path):
    assert get_last_hash(str(tmp_path / "audit.log")) == GENESIS


def test_append_returns_sha256_hex(tmp_path):
    log = str(tmp_path / "audit.log")
    h = append_audit_log(log, "init", "vault", True, GENESIS)
    assert len(h) == 64


def test_hash_chain_links_entries(tmp_path):
    log = str(tmp_path / "audit.log")
    first = append_audit_log(log, "init", "vault", True, GENESIS)
    assert get_last_hash(log) == first

    second = append_audit_log(log, "add", "gmail", True, first)
    assert get_last_hash(log) == second
    assert first != second