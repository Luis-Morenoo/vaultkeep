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