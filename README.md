# VaultKeep

![CI](https://github.com/Luis-Morenoo/vaultkeep/actions/workflows/ci.yml/badge.svg)

A local-first password manager in Python, built to practice secure design end to end: threat modeling first, then authenticated encryption, memory-hard key derivation, a tamper-evident audit log, a JWT-protected web API — and finally attacking it to check the defenses hold.

> **Not for real passwords.** VaultKeep is a learning and portfolio project and has not been independently audited. Use a maintained password manager for anything that matters.

## Security design

| Concern | Approach |
|---|---|
| Master password → key | **Argon2id** (t=3, m=64 MiB, p=4, 128-bit random salt per vault). Memory-hard, so GPU brute force is expensive. KDF settings read from a file are bounds-checked before any work is done. |
| Encryption at rest | **AES-256-GCM**, fresh 96-bit random nonce per entry. Username, password and notes are encrypted together as one payload. |
| Password check & header integrity | A known value is encrypted with the vault key, using the whole header as associated data. Unlocking verifies it first, so a wrong password fails even on an empty vault, and any header edit is detected. |
| Entry integrity | Each entry's GCM tag covers `vault_id ‖ item_id ‖ service`, so entries can't be swapped between vaults or positions, and service names can't be relabelled. |
| Safe writes | The vault is written to a private temp file and atomically swapped into place, so a crash can't leave a half-written vault. |
| Timing leaks | Secret comparisons use `hmac.compare_digest` (constant time). |
| Audit trail | Append-only JSON-lines log; each record stores the SHA-256 of the previous one, so edits or deletions break the chain. Failed unlocks are logged. |
| Web API | Short-lived **JWT** (HS256, 15 min, algorithm pinned, bound to one vault). The app refuses to start without a ≥32-byte signing key from the environment. Rate limits on every route that accepts the master password (login 5/min, vault routes 30/min per IP). |
| Browser | Strict Content Security Policy with no inline script, `X-Frame-Options: DENY`, `nosniff`, `no-store`; vault data rendered with `textContent`, never `innerHTML`. |
| Secrets in URLs | Requests that carry the master password are `POST`, so it never lands in URLs or server logs. |
| Container | Runs as a non-root user on a read-only file system with all capabilities dropped, served by gunicorn, and published on `127.0.0.1` only. |

## Threat model (summary)

**Assets:** stored credentials, the master password, the JWT signing key.

| Threat | Attacker capability | Mitigation | Status |
|---|---|---|---|
| Stolen disk or copied `vault.json` | Reads the file offline | AES-256-GCM; key exists only as Argon2id(master password, salt) | Mitigated |
| Offline brute force of the master password | Has the file, unlimited time | Argon2id t=3, m=64 MiB, p=4 makes each guess cost real memory and time | Mitigated, given a strong password |
| Online brute force via the web UI | Network access to the API | Rate limits on every route that takes the master password; UI bound to localhost | Mitigated |
| Wrong password accepted on an empty vault | Can reach the CLI or login page | Header key check (format v2) | Mitigated |
| Ciphertext tampering, entry swapping, header edits | Can write the file | GCM tags with vault, item and service binding; authenticated header; KDF bounds | Mitigated; whole-entry deletion and rollback to an older file aren't detected |
| Forged session tokens | Knows the signing key | HS256, algorithm pinned, 15-minute expiry, token bound to the vault ID; no default key | Mitigated while the key stays secret |
| Audit-log editing | Can write the log | SHA-256 hash chain | Tamper-evident only; a full consistent rewrite isn't detected |
| Malware on the host, memory scraping | Code execution as the user | Out of scope | Accepted |

**Trust boundaries:** the local OS and file system are trusted; the network, the vault file at rest and anything reaching the web API are not. VaultKeep is built for single-user, local use and is not meant to be exposed beyond `localhost`.

The full threat model — in scope, out of scope, trust boundaries — is in [THREAT_MODEL.md](THREAT_MODEL.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Attacking it

`attacks/` contains three scripts that test the defenses rather than just describe them:

- **`brute_force_sim.py`** — dictionary attack against a real vault. Each guess pays the full Argon2id cost (~0.05 s measured on a Ryzen 7 5800XT), which turns a 14M-entry wordlist into days of compute instead of seconds against a fast hash.
- **`tamper_sim.py`** — flips bytes in a stored ciphertext, then loads the vault with the *correct* password. Decryption is refused because the GCM tag no longer verifies.
- **`timing_attack.py`** — times `==` against `hmac.compare_digest` on matching, early-mismatch and late-mismatch inputs to show why constant-time comparison matters.

```bash
python -m attacks.brute_force_sim ~/.vaultkeep/vault.json
python -m attacks.tamper_sim ~/.vaultkeep/vault.json ~/.vaultkeep/tampered.json <master-password>
python -m attacks.timing_attack
```

## Quick start

### CLI

```bash
python -m venv venv && source venv/bin/activate   # Windows Git Bash: source venv/Scripts/activate
pip install -r requirements.txt

python -m vaultkeep.cli init                       # create a vault (asks for a master password twice)
python -m vaultkeep.cli add gmail                  # prompts for username, password, master password
python -m vaultkeep.cli get gmail                  # shows every account stored for gmail
python -m vaultkeep.cli list
python -m vaultkeep.cli delete gmail --username luis
```

Passwords are prompted with hidden input. The `--password` and `--master-password` flags exist for scripting and tests, but anything passed as a flag ends up in your shell history, so prefer the prompts. The vault lives in `~/.vaultkeep/`; set `VAULTKEEP_HOME` to use another folder.

### Web UI + API (Docker)

```bash
# one-time: create .env with a 256-bit signing key (the app won't start without one)
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste the output after VAULTKEEP_SECRET_KEY=

# one-time: create a vault inside the persistent volume
docker compose run --rm vaultkeep python -m vaultkeep.cli init

docker compose up -d --build     # http://127.0.0.1:5000
docker compose down
```

The vault lives in the `vaultkeep-data` volume and survives restarts. `.env` is excluded by both `.gitignore` and `.dockerignore`, so the key never reaches the repo or the image. To start over, `docker compose down -v` deletes the volume and the vault in it.

For local development without Docker, `python run.py` serves on `127.0.0.1:5000` with the same `VAULTKEEP_SECRET_KEY` requirement. Debug mode stays off unless you set `VAULTKEEP_DEBUG=1`.

### API

| Method | Path | Body |
|---|---|---|
| `POST` | `/auth/login` | `password` → returns a JWT |
| `POST` | `/vault/entries/list` | `password` → `[{service, username}]` |
| `POST` | `/vault/entries` | `password, service, username, entry_password` |
| `DELETE` | `/vault/entries/<service>` | `password`, optional `username` |

All `/vault/*` routes need `Authorization: Bearer <token>`. Entries are unique per **service + username**, so one service can hold several accounts.

## Vault format

The current format is **v2**. Vaults created by earlier versions (v1) still open and are upgraded to v2 automatically on the next save. An empty v1 vault is refused, because without any entries its password can't be verified; delete it and run `init` again.

## Development

```bash
pip install -r requirements-dev.txt     # runtime + test, lint and security tools
pytest tests/ -v
pip install pre-commit && pre-commit install   # gitleaks, Bandit and black before every commit
bash scripts/security-scan.sh --fresh   # gitleaks, trufflehog, Bandit, Semgrep, pip-audit (needs Docker)
```

The tests cover encryption round-trips, wrong-key and tampering rejection, the header key check, service-name binding, KDF bounds, v1 → v2 migration, atomic writes, the hash chain, CLI flows via Click's `CliRunner`, and the web layer: the fail-closed signing key, security headers, token binding and rate limiting. GitHub Actions runs the tests plus gitleaks, Bandit and pip-audit on every push; actions are pinned to commit SHAs and Dependabot keeps dependencies current.

## Project layout

```
vaultkeep/
├── kdf.py        Argon2id key derivation, verification and KDF bounds
├── crypto.py     AES-256-GCM encrypt/decrypt
├── vault.py      vault format v2: authenticated header, entry binding, atomic writes
├── audit.py      SHA-256 hash-chained audit log
├── models.py     dataclasses: header, KDF params, entries, audit records
├── cli.py        Click CLI
└── web/          Flask app, JWT auth, rate limiting, security headers, templates and static JS
attacks/          brute force, tamper and timing simulations
scripts/          security-scan.sh and pin-actions.sh
tests/            pytest suite
```

## Known limitations

Documented on purpose — each is a deliberate scope decision or a known gap:

- **No separate data key yet.** Entries are encrypted directly with the Argon2id-derived key. The header reserves a `wrapped_data_key` field for envelope encryption.
- **No memory zeroization.** Python strings are immutable and garbage-collected, so plaintext can linger in process memory. Malware on the host is out of scope (see the threat model).
- **Service names are visible.** They're authenticated, so they can't be altered, but they're stored in plaintext: anyone with the file can see *which* services you have accounts with.
- **Deletion and rollback aren't detected.** Removing a whole entry, or restoring an older copy of the file, leaves a valid vault. Catching that needs a commitment stored outside the file.
- **Web actions aren't audit-logged.** The hash-chained log records CLI operations only.
- **Audit chain is tamper-evident, not tamper-proof.** Someone with write access could rewrite the entire log consistently.
- **Local, single-user only.** Plain HTTP on `localhost`; not designed to be exposed to a network.
- **Re-entering the master password.** The JWT proves login but doesn't carry the decryption key, so each vault request re-sends the master password and re-derives the key.

## Roadmap (v2)

- **Breached-password check** — warn on `add` if a password appears in known breach lists, using a local Bloom filter so the password never leaves the machine
- **Envelope encryption** — random DEK wrapped by the password-derived KEK, so changing the master password re-wraps one key instead of re-encrypting every entry
- **AWS deployment** — IAM least privilege, Secrets Manager for the signing key, VPC isolation, TLS
- **Encrypted service names** to remove metadata leakage
- **Rollback protection** and **audit logging for web routes**
- **Item-ID addressing** and refresh tokens for the API

## License

[MIT](LICENSE)
