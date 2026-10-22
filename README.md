# VaultKeep

![CI](https://github.com/Luis-Morenoo/vaultkeep/actions/workflows/ci.yml/badge.svg)

A local-first password manager in Python, built to practice secure design end to end: threat modeling first, then authenticated encryption, memory-hard key derivation, a tamper-evident audit log, a JWT-protected web API — and finally attacking it to check the defenses hold.

> **Not for real passwords.** VaultKeep is a learning and portfolio project and has not been independently audited. Use a maintained password manager for anything that matters.

## Security design

| Concern | Approach |
|---|---|
| Master password → key | **Argon2id** (t=3, m=64 MiB, p=4, 128-bit random salt per vault). Memory-hard, so GPU brute force is expensive. |
| Encryption at rest | **AES-256-GCM**, fresh 96-bit random nonce per entry. Username, password and notes are encrypted together as one payload. |
| Tamper detection | GCM's authentication tag fails on any modified byte. Each entry binds `vault_id ‖ item_id` as associated data, so entries can't be swapped between vaults or positions. |
| Timing leaks | Secret comparisons use `hmac.compare_digest` (constant time). |
| Audit trail | Append-only JSON-lines log; each record stores the SHA-256 of the previous one, so edits or deletions break the chain. |
| Web API | Short-lived **JWT** (HS256, 15 min), rate-limited login (5/min per IP), signing key from the environment — never in code. |
| Secrets in URLs | Requests that carry the master password are `POST`, so it never lands in URLs or server logs. |
| XSS | The dashboard renders vault data with `textContent`, never `innerHTML`, so a stored value can't inject script. |

The full threat model — in scope, out of scope, trust boundaries — is in [THREAT_MODEL.md](THREAT_MODEL.md).

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

Passwords are always prompted with hidden input, never passed as arguments, so they don't end up in shell history.

### Web UI + API (Docker)

```bash
# one-time: create .env with a 256-bit signing key
echo "VAULTKEEP_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env

# one-time: create a vault inside the persistent volume
docker compose run --rm vaultkeep python -m vaultkeep.cli init

docker compose up -d --build     # http://127.0.0.1:5000
docker compose down
```

The vault lives in the `vaultkeep-data` volume and survives container restarts. `.env` is excluded by both `.gitignore` and `.dockerignore`, so the key never reaches the repo or the image.

### API

| Method | Path | Body |
|---|---|---|
| `POST` | `/auth/login` | `password` → returns a JWT |
| `POST` | `/vault/entries/list` | `password` → `[{service, username}]` |
| `POST` | `/vault/entries` | `password, service, username, entry_password` |
| `DELETE` | `/vault/entries/<service>` | `password`, optional `username` |

All `/vault/*` routes need `Authorization: Bearer <token>`. Entries are unique per **service + username**, so one service can hold several accounts.

## Tests

```bash
pytest tests/ -v
```

Covers encrypt/decrypt round-trips, wrong-key and tampered-ciphertext rejection, key derivation, hash-chain linking, vault save/load, and end-to-end CLI flows via Click's `CliRunner`. GitHub Actions runs the suite on every push to `main`.

## Project layout

```
vaultkeep/
├── kdf.py        Argon2id key derivation and verification
├── crypto.py     AES-256-GCM encrypt/decrypt
├── vault.py      JSON vault serialization (base64 for binary fields)
├── audit.py      SHA-256 hash-chained audit log
├── models.py     dataclasses: header, KDF params, entries, audit records
├── cli.py        Click CLI
└── web/          Flask app, JWT auth, rate limiting, templates
attacks/          brute force, tamper and timing simulations
tests/            pytest suite
```

## Known limitations

Documented on purpose — every item below is a deliberate v1 scope decision or a known gap:

- **No separate data key yet.** Entries are encrypted directly with the Argon2id-derived key. The header reserves a `wrapped_data_key` field for envelope encryption, but it isn't used in v1.
- **No memory zeroization.** Python strings are immutable and garbage-collected, so plaintext can linger in process memory. Malware on the host is explicitly out of scope (see the threat model).
- **Service names are stored in plaintext.** Credentials are encrypted, but anyone with the file can see *which* services you have accounts with. A deliberate trade-off for fast listing.
- **Web actions aren't audit-logged.** The hash-chained log currently records CLI operations only.
- **Audit chain is tamper-evident, not tamper-proof.** Someone with write access could rewrite the entire log consistently; anchoring it externally would close that.
- **Development server.** Flask's built-in server, local use only. Not deployed publicly — a password manager exposed to the internet would need far more hardening than v1 provides.
- **Re-entering the master password.** The JWT proves login but doesn't carry the decryption key, so each vault request re-sends the master password and re-derives the key.

## Roadmap (v2)

- **Breached-password check** — warn on `add` if a password appears in known breach lists, using a local Bloom filter so the password never leaves the machine
- **Envelope encryption** — random DEK wrapped by the password-derived KEK, so changing the master password re-wraps one key instead of re-encrypting every entry
- **AWS deployment** — IAM least privilege, Secrets Manager for the signing key, VPC isolation, a production WSGI server
- **Encrypted service names** to remove metadata leakage
- **Audit logging for web routes**, matching the CLI
- **Item-ID addressing** and refresh tokens for the API
