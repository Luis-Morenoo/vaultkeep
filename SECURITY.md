# Security Policy

VaultKeep is a personal learning and portfolio project. It has not been
independently audited and should not be used to store real credentials.
Security reports are still very welcome, and I'll treat them seriously.

## Supported versions

Only the latest commit on `main` is supported. There are no maintained release branches.

## Reporting a vulnerability

**Please don't open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Include:

- what you found and where (file, function or endpoint)
- steps or a proof of concept to reproduce it
- the impact you expect (what an attacker gains)

This is a one-person project, so responses are best effort. I aim to acknowledge
reports within 7 days and to agree on a disclosure timeline with you before
anything is published. Credit is given in the fix commit unless you'd rather not be named.

## Scope

In scope:

- the vault format and cryptography (`vaultkeep/vault.py`, `crypto.py`, `kdf.py`)
- the CLI and the web API, including authentication, rate limiting and the dashboard
- the audit log's hash chain
- the Docker configuration

Out of scope, as described in [THREAT_MODEL.md](THREAT_MODEL.md):

- attackers who already run code on the user's machine (malware, debuggers, memory scraping)
- weak master passwords chosen by the user
- exposing the web interface beyond `localhost`, which the project explicitly doesn't support
- denial of service against a local, single-user process

## Design summary

- Argon2id key derivation (t=3, m=64 MiB, p=4, random 128-bit salt per vault)
- AES-256-GCM for every entry, with the vault ID, item ID and service name as associated data
- An authenticated header (format v2) so wrong passwords and header edits are detected before any entry is decrypted
- Short-lived HS256 JWTs for the web API, a signing key that must come from the environment, and rate limits on every route that accepts the master password

Known limitations are listed in the [README](README.md#known-limitations).
