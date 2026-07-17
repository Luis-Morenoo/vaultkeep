""" Command-line interface for the vaultkeep application """

import click
import os
import sys
from .vault import load_vault, save_vault
from .models import VaultFile, VaultHeader, VaultEntry, KDFParameters
from .utils import generate_random_bytes, build_aad
from .audit import append_audit_log, get_last_hash

VAULT_PATH = os.path.expanduser("~/.vaultkeep/vault.json")  # Default path to the vault file in the user's home directory
AUDIT_LOG_PATH = os.path.expanduser("~/.vaultkeep/audit.log")  # Default path to the audit log file in the user's home directory

@click.group()
def cli():
    """ VaultKeep CLI - A secure password manager """
    pass

@cli.command()
@click.option("--password", prompt=True, hide_input=True, 
              confirmation_prompt=True, help="Master password for the vault")
def init(password):
    """ Initialize a new VaultKeep vault."""

    # Check if vault already exists
    if os.path.exists(VAULT_PATH):
        click.echo("A vault already exists at this location. Use a different path or delete the existing vault first.")
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
    append_audit_log(
        path=AUDIT_LOG_PATH,
        operation="init",
        item_id="vault",
        success=True,
        prior_hash="0" * 64
    )

    # Print success message
    click.echo("Vault created successfully! Run 'vaultkeep add' to store your first password.")

@cli.command()
@click.argument("service")
@click.option("--username", prompt=True, help="Username for the service")
@click.option("--password", prompt=True, hide_input=True, 
              help="Password for the service")
@click.option("--master-password", prompt="Master password", hide_input=True, 
              help="Master password to unlock the vault")
def add(service, username, password, master_password):
    """Add a new password entry to the vault."""

    # Load the vault from disk using the master password
    vault = load_vault(master_password.encode("utf-8"), VAULT_PATH)

    # Create a new VaultEntry with a random item_id
    entry = VaultEntry(
        item_id= generate_random_bytes(16),
        service= service,
        username= username,
        password= password
    )

    # Append the new entry to the vault
    vault.entries.append(entry)

    # Save the vault back to disk
    save_vault(vault, master_password.encode("utf-8"), VAULT_PATH)

    # Get last hash and append audit log entry
    prior_hash = get_last_hash(AUDIT_LOG_PATH)
    append_audit_log(
        path=AUDIT_LOG_PATH,
        operation="add",
        item_id=entry.item_id.hex(),
        success=True,
        prior_hash=prior_hash
    )

    # Print success message
    click.echo("Success password added successfully")

@cli.command()
@click.argument("service")
@click.option("--master-password", prompt="Master password", hide_input=True,
              help="Master password to unlock the vault")
def get(service, master_password):
    """Retrieve a password entry from the vault."""

    # Load the vault from the disk using the master password
    vault = load_vault(master_password.encode("utf-8"), VAULT_PATH)

    # Get prior hash before the loop so both branches can use it
    prior_hash = get_last_hash(AUDIT_LOG_PATH)

    # Search vault.entries for an entry where entry.service == service
    for entry in vault.entries:
        if entry.service == service:
            click.echo(f"Username: {entry.username}")
            click.echo(f"Password: {entry.password}")
            append_audit_log(AUDIT_LOG_PATH, "get", service, True, prior_hash)
            break
    else:
        click.echo("No entry found for this service")
        append_audit_log(AUDIT_LOG_PATH, "get", service, False, prior_hash)

@cli.command(name="list")
@click.option("--master-password", prompt="Master password", hide_input=True,
              help="Master password to unlock the vault")
def list_entries(master_password):
    """ List the services in the vault entries """

    # Load the vault from the disk using the master password
    vault = load_vault(master_password.encode("utf-8"), VAULT_PATH)

    # Check if vault.entries is empty, if so print "Vault is empty"
    if not vault.entries:
        click.echo("Vault is empty")
        return
    
    # Loop through entries and display each service
    for entry in vault.entries:
        click.echo(f"Service: {entry.service}")

    # Get last hash and append audit log entry
    prior_hash = get_last_hash(AUDIT_LOG_PATH)
    append_audit_log(
        path=AUDIT_LOG_PATH,
        operation="list",
        item_id="vault",
        success=True,
        prior_hash=prior_hash
    )

@cli.command()
@click.argument("service")
@click.option("--master-password", prompt="Master password", hide_input=True,
              help="Master password to unlock the vault")
def delete(service, master_password):
    """ Delete the service from the vault entries"""
    
    # Load the vault from the disk using the master password
    vault = load_vault(master_password.encode("utf-8"), VAULT_PATH) 

    # Find the entry where entry.service == service
    for entry in vault.entries:
        if entry.service == service:
            vault.entries.remove(entry)
            save_vault(vault, master_password.encode("utf-8"), VAULT_PATH)
            prior_hash = get_last_hash(AUDIT_LOG_PATH)
            append_audit_log(AUDIT_LOG_PATH, "delete", entry.item_id.hex(), True, prior_hash)
            click.echo(f"Entry for {service} deleted successfully.")
            break
    else:
        prior_hash = get_last_hash(AUDIT_LOG_PATH)
        append_audit_log(AUDIT_LOG_PATH, "delete", service, False, prior_hash)
        click.echo(f"No entry found for {service}")

if __name__ == "__main__":
    cli()
