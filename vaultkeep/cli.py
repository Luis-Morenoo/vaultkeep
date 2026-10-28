"""Command-line interface for the vaultkeep application"""

import click
import os
import sys
from .vault import load_vault, save_vault
from .models import VaultFile, VaultHeader, VaultEntry, KDFParameters
from .utils import generate_random_bytes
from .audit import append_audit_log, get_last_hash

# Vault folder: ~/.vaultkeep by default, overridable with VAULTKEEP_HOME
VAULT_DIR = os.path.expanduser(os.environ.get("VAULTKEEP_HOME", "~/.vaultkeep"))
VAULT_PATH = os.path.join(VAULT_DIR, "vault.json")  # Encrypted vault file
AUDIT_LOG_PATH = os.path.join(VAULT_DIR, "audit.log")  # Hash-chained audit log


def _unlock(master_password):
    """Load the vault, turning errors into clean CLI messages instead of tracebacks.
    Failed unlocks are written to the audit log."""
    if not os.path.exists(VAULT_PATH):
        raise click.ClickException("No vault found. Run 'init' first.")
    try:
        return load_vault(master_password.encode("utf-8"), VAULT_PATH)
    except ValueError as exc:
        append_audit_log(AUDIT_LOG_PATH, "unlock", "vault", False, get_last_hash(AUDIT_LOG_PATH))
        raise click.ClickException(str(exc))


@click.group()
def cli():
    """VaultKeep CLI - A secure password manager"""
    pass


@cli.command()
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Master password for the vault",
)
def init(password):
    """Initialize a new VaultKeep vault."""

    # Check if vault already exists
    if os.path.exists(VAULT_PATH):
        click.echo(
            "A vault already exists at this location. Use a different path or delete the existing vault first."
        )
        return

    # Create vault directory if it doesnt exist
    os.makedirs(os.path.dirname(VAULT_PATH), exist_ok=True)

    # Generate random vault_id and salt
    vault_id = generate_random_bytes(16)
    salt = generate_random_bytes(16)

    # Create KDFParameters with the random salt
    kdf_params = KDFParameters(salt=salt)

    # Create VaultHeader
    header = VaultHeader(vault_id=vault_id, kdf_params=kdf_params)

    # Create empty VaultFile
    vault = VaultFile(header=header)

    # Save vault to disk
    save_vault(vault, password.encode("utf-8"), VAULT_PATH)

    # Append an audit log entry for the vault initialization
    # (chains onto any existing log instead of restarting at the genesis hash)
    append_audit_log(
        path=AUDIT_LOG_PATH,
        operation="init",
        item_id="vault",
        success=True,
        prior_hash=get_last_hash(AUDIT_LOG_PATH),
    )

    # Print success message
    click.echo(
        "Vault created successfully! Run 'vaultkeep add' to store your first password."
    )


def _matches(vault, service, username=None):
    """Return entries for a service, optionally narrowed to one username."""
    return [
        e
        for e in vault.entries
        if e.service == service and (username is None or e.username == username)
    ]


@cli.command()
@click.argument("service")
@click.option("--username", prompt=True, help="Username for the service")
@click.option(
    "--password", prompt=True, hide_input=True, help="Password for the service"
)
@click.option(
    "--master-password",
    prompt="Master password",
    hide_input=True,
    help="Master password to unlock the vault",
)
def add(service, username, password, master_password):
    """Add a new password entry to the vault."""

    # Load the vault from disk using the master password
    vault = _unlock(master_password)

    # Entries are unique on (service, username) - one service can hold many accounts
    if _matches(vault, service, username):
        click.echo(f"An entry for {username} on {service} already exists.")
        return

    # Create a new VaultEntry with a random item_id
    entry = VaultEntry(
        item_id=generate_random_bytes(16),
        service=service,
        username=username,
        password=password,
    )

    # Append the new entry and save the vault back to disk
    vault.entries.append(entry)
    save_vault(vault, master_password.encode("utf-8"), VAULT_PATH)

    # Get last hash and append audit log entry
    prior_hash = get_last_hash(AUDIT_LOG_PATH)
    append_audit_log(
        path=AUDIT_LOG_PATH,
        operation="add",
        item_id=entry.item_id.hex(),
        success=True,
        prior_hash=prior_hash,
    )

    click.echo(f"Entry for {username} on {service} added successfully.")


@cli.command()
@click.argument("service")
@click.option("--username", default=None, help="Show only this account (optional)")
@click.option(
    "--master-password",
    prompt="Master password",
    hide_input=True,
    help="Master password to unlock the vault",
)
def get(service, username, master_password):
    """Retrieve the password entries for a service."""

    # Load the vault from the disk using the master password
    vault = _unlock(master_password)
    prior_hash = get_last_hash(AUDIT_LOG_PATH)

    matches = _matches(vault, service, username)
    if not matches:
        click.echo("No entry found for this service")
        append_audit_log(AUDIT_LOG_PATH, "get", service, False, prior_hash)
        return

    # A service can hold several accounts - show each one
    for i, entry in enumerate(matches):
        if i:
            click.echo("")
        click.echo(f"Username: {entry.username}")
        click.echo(f"Password: {entry.password}")

    append_audit_log(AUDIT_LOG_PATH, "get", service, True, prior_hash)


@cli.command(name="list")
@click.option(
    "--master-password",
    prompt="Master password",
    hide_input=True,
    help="Master password to unlock the vault",
)
def list_entries(master_password):
    """List the services in the vault entries"""

    # Load the vault from the disk using the master password
    vault = _unlock(master_password)

    # Check if vault.entries is empty, if so print "Vault is empty"
    if not vault.entries:
        click.echo("Vault is empty")
        return

    # Loop through entries and display each service
    for entry in vault.entries:
        click.echo(f"Service: {entry.service} ({entry.username})")

    # Get last hash and append audit log entry
    prior_hash = get_last_hash(AUDIT_LOG_PATH)
    append_audit_log(
        path=AUDIT_LOG_PATH,
        operation="list",
        item_id="vault",
        success=True,
        prior_hash=prior_hash,
    )


@cli.command()
@click.argument("service")
@click.option(
    "--username",
    default=None,
    help="Account to delete (required when the service has more than one)",
)
@click.option(
    "--master-password",
    prompt="Master password",
    hide_input=True,
    help="Master password to unlock the vault",
)
def delete(service, username, master_password):
    """Delete an entry from the vault."""

    # Load the vault from the disk using the master password
    vault = _unlock(master_password)
    prior_hash = get_last_hash(AUDIT_LOG_PATH)

    matches = _matches(vault, service, username)
    if not matches:
        append_audit_log(AUDIT_LOG_PATH, "delete", service, False, prior_hash)
        click.echo(f"No entry found for {service}")
        return

    # Several accounts and no username given - refuse rather than guess
    if username is None and len(matches) > 1:
        names = ", ".join(e.username for e in matches)
        append_audit_log(AUDIT_LOG_PATH, "delete", service, False, prior_hash)
        click.echo(
            f"{service} has {len(matches)} accounts ({names}). "
            "Use --username to choose one."
        )
        return

    entry = matches[0]
    vault.entries.remove(entry)
    save_vault(vault, master_password.encode("utf-8"), VAULT_PATH)
    append_audit_log(AUDIT_LOG_PATH, "delete", entry.item_id.hex(), True, prior_hash)
    click.echo(f"Entry for {entry.username} on {service} deleted successfully.")

if __name__ == "__main__":
    cli()
