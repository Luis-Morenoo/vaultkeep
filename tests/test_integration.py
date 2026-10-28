from click.testing import CliRunner
from vaultkeep import cli as cli_module


def test_cli_init_add_get(tmp_path, monkeypatch):
    # Point the CLI at a throwaway folder instead of ~/.vaultkeep
    monkeypatch.setattr(cli_module, "VAULT_PATH", str(tmp_path / "vault.json"))
    monkeypatch.setattr(cli_module, "AUDIT_LOG_PATH", str(tmp_path / "audit.log"))

    runner = CliRunner()

    result = runner.invoke(cli_module.cli, ["init", "--password", "Test123"])
    assert result.exit_code == 0

    result = runner.invoke(cli_module.cli, [
        "add", "gmail",
        "--username", "luis@gmail.com",
        "--password", "SuperSecret",
        "--master-password", "Test123",
    ])
    assert result.exit_code == 0

    result = runner.invoke(cli_module.cli, ["get", "gmail", "--master-password", "Test123"])
    assert "Username: luis@gmail.com" in result.output
    assert "Password: SuperSecret" in result.output

def test_cli_multiple_accounts_per_service(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "VAULT_PATH", str(tmp_path / "vault.json"))
    monkeypatch.setattr(cli_module, "AUDIT_LOG_PATH", str(tmp_path / "audit.log"))
    runner = CliRunner()
    mp = ["--master-password", "Test123"]

    runner.invoke(cli_module.cli, ["init", "--password", "Test123"])
    runner.invoke(cli_module.cli, ["add", "gmail", "--username", "luis", "--password", "a", *mp])
    runner.invoke(cli_module.cli, ["add", "gmail", "--username", "coco", "--password", "b", *mp])

    # same service + username is rejected
    result = runner.invoke(cli_module.cli, ["add", "gmail", "--username", "luis", "--password", "c", *mp])
    assert "already exists" in result.output

    # get shows both accounts
    result = runner.invoke(cli_module.cli, ["get", "gmail", *mp])
    assert "Username: luis" in result.output and "Username: coco" in result.output

    # delete without a username is refused when ambiguous
    result = runner.invoke(cli_module.cli, ["delete", "gmail", *mp])
    assert "Use --username" in result.output

    # delete with a username removes only that account
    runner.invoke(cli_module.cli, ["delete", "gmail", "--username", "coco", *mp])
    result = runner.invoke(cli_module.cli, ["get", "gmail", *mp])
    assert "Username: luis" in result.output and "coco" not in result.output


def test_cli_wrong_password_is_a_clean_error_and_is_audited(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "VAULT_PATH", str(tmp_path / "vault.json"))
    monkeypatch.setattr(cli_module, "AUDIT_LOG_PATH", str(tmp_path / "audit.log"))
    runner = CliRunner()

    runner.invoke(cli_module.cli, ["init", "--password", "Test123"])

    # empty vault + wrong password: refused, no traceback, exit code 1
    result = runner.invoke(cli_module.cli, ["list", "--master-password", "WrongPass"])
    assert result.exit_code == 1
    assert "Wrong master password" in result.output
    assert "Traceback" not in result.output

    with open(tmp_path / "audit.log") as f:
        last = f.readlines()[-1]
    assert '"operation": "unlock"' in last and '"success": false' in last


def test_cli_without_a_vault_says_run_init(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "VAULT_PATH", str(tmp_path / "vault.json"))
    monkeypatch.setattr(cli_module, "AUDIT_LOG_PATH", str(tmp_path / "audit.log"))
    result = CliRunner().invoke(cli_module.cli, ["list", "--master-password", "x"])
    assert result.exit_code == 1 and "init" in result.output
