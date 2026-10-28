# VaultKeep Threat Model & Architecture

## Threat Model

### Primary Threats (In Scope for v1)

1. **Stolen or Lost Laptop**
   - Attacker has physical access to the device and can extract the vault file from disk
   - **Defense:** Vault file encrypted with AES-256-GCM; master password is hashed with Argon2id (intentionally slow to make brute-force attacks computationally expensive)
   - **Assumption:** Master password is strong (user responsibility; we document best practices in README)

2. **Master Password Brute-Force Attack**
   - Attacker has the encrypted vault file and attempts to guess the master password
   - **Defense:** Argon2id with RFC 9106 SECOND RECOMMENDED parameters (t=3, m=65536 KiB [64 MiB], p=4, 128-bit salt)
   - **Cost:** ~0.05 s per guess measured on a Ryzen 7 5800XT; a 14M-entry wordlist would take roughly 8 days on one machine
   - **Residual Risk:** Weak master passwords (< 12 chars, no mixed case/symbols) can be cracked faster; user education required

3. **Plaintext Password Exposure During Use**
   - Attacker with code execution while the app runs could intercept passwords in memory
   - **Defense:** No plaintext passwords are logged. Python cannot reliably wipe secrets from memory (immutable strings, garbage collection), so in-memory exposure is accepted as a residual risk
   - **Residual Risk:** Out of scope — a compromised OS or debugger can always read running process memory; this is a system-level threat

### Secondary Threats (Out of Scope for v1)

1. **Malware on Machine**
   - Attacker has code execution while the app runs
   - **Why out of scope:** If malware is running, it can keystroke-log, capture screenshots, or read process memory regardless of our encryption
   - **Mitigation path:** TOTP unlock (v2) + biometric unlock (v3, OS integration) make this harder

2. **Government/Law Enforcement Access**
   - Attacker with legal authority demands passwords or the vault
   - **Why out of scope:** At that point, the threat model is political/legal, not technical
   - **Principle:** We encrypt, we don't hide

3. **Vault File Tampering**
   - Attacker modifies the encrypted vault file, hoping to trick the app into leaking secrets or crashing in a way that exposes data
   - **Defense (format v2):** the header is authenticated by a key-check value encrypted with the whole header as associated data, so a wrong password or any header edit is rejected before entries are touched, even for an empty vault. Each entry's AEAD tag covers `vault_id || item_id || service`, so ciphertexts and service names can't be swapped. KDF settings are bounds-checked before any key derivation, so a tampered header can't request absurd memory or time costs.
   - **Residual risk:** deleting a whole entry, or replacing the file with an older valid copy (rollback), isn't detected; that needs a vault-wide commitment anchored outside the file

---

## Trust Boundaries

### What We Trust

1. **The Client Machine (Your Computer)**
   - We assume the OS kernel, file system, and hardware are not fundamentally compromised
   - We do NOT assume malware is impossible; we assume it's the user's responsibility to keep their machine clean (antivirus, updates, etc.)

2. **The User's Master Password**
   - We assume the user can choose and remember a strong password
   - We assume the password is not shared, logged, or reused elsewhere

3. **The Vault File on Disk**
   - We assume the file is where we left it and hasn't been replaced by an attacker's copy
   - We do NOT assume the file is private; in fact, we assume an attacker can read it

### What We Don't Trust

1. **The Network (v1)**
   - VaultKeep is an offline-first CLI; no network transmission of vault data in v1
   - Phase 2 will address cloud sync with OAuth 2.1 + PKCE + DPoP

2. **Third-Party Services (v1)**
   - No cloud backup, no Have I Been Pwned checks in v1
   - All operations are local only

3. **The Operating System's Built-in "Secure" Storage**
   - Windows Credential Manager, macOS Keychain, Linux pass — these are convenient but not part of VaultKeep's threat model
   - We provide our own encryption; users can optionally store the vault file in OS secure storage if they want

---

## Cryptographic Primitives & Design

### Key Derivation

- **Algorithm:** Argon2id (IETF RFC 9106)
- **Parameters:** t=3, m=65536 KiB (64 MiB), p=4, salt=128 bits, tag=256 bits
- **Why:** Memory-hard and GPU-resistant; brute-force is prohibitively expensive
- **Output:** 256-bit key used directly as the AES-256-GCM key (envelope encryption with a separate data key is planned for v2)

### Encryption

- **Primary Cipher:** AES-256-GCM
  - 256-bit key, 96-bit nonce (random), 128-bit authentication tag
  - NIST FIPS 197 approved; hardware-accelerated on modern CPUs

### Integrity & Binding

- **Header key check (v2):** a fixed value encrypted with the vault key, using the canonical header as AAD; verified first on every unlock
- **Entry binding (v2):** `vault_id || item_id || service` as AAD on every entry
  - Prevents cut-and-paste attacks between items or vaults, and relabelling entries
  - Tag is verified before any plaintext is returned
- **Migration:** v1 vaults (AAD `vault_id || item_id`, no key check) still load and are rewritten as v2 on the next save; an empty v1 vault is refused because its password can't be verified

### Memory Management

- Secrets are not logged or written to disk in plaintext. Memory zeroization isn’t feasible in pure Python and is listed under residual risks

### Audit Trail

- Append-only JSON-lines audit log
- Each entry: timestamp, operation, item_id (not value), success/failure
- Hash chain: SHA-256 hash of previous entry included in next entry (tampering detectable)
- Maps to SOC 2 CC6 (logical access) and CC7 (monitoring) controls

---

## What's NOT Happening in v1 (Non-Goals)

### Explicitly Out of Scope

- **WebAuthn / Passkey Unlock** — Stretch goal for v2; requires OS integration
- **TOTP or Biometric Second Factor** — v1.5 goal; clock-sync and hardware integration are separate concerns
- **Cloud Sync / Network Transport** — Requires OAuth 2.1 + PKCE; v2
- **HSM / TPM Backing** — Trait designed to support it; not implemented
- **FIPS 140-3 Validation** — Would require accredited lab testing (12+ months); we use FIPS-approved primitives but make no validation claim
- **Post-Quantum KEMs** — ML-KEM (FIPS 203) relevant for future transport; not for v1 local storage
- **Secrets Rotation** — Planned for v2; would need per-item version tracking
- **Access Control Lists (ACLs)** — Single-user CLI only in v1; multi-user/org features in v2+

### Design Hooks (Extensibility Points)

We *will* design the code so these can be added without rewriting the vault format:

1. Cipher field: header stores the cipher name (aes-256-gcm)
2. KDF parameters: header stores algorithm, salt and costs, so they can change without breaking existing vaults
3. Version field: allows a migration path for future format changes (used for the v1 → v2 upgrade)
4. Reserved wrapped_data_key field: placeholder for v2 envelope encryption

---

## Residual Risks (Honest Assessment)

1. **Weak Master Password:** We can't enforce password strength; user responsibility
2. **Coredumps / Swap:** If the OS writes memory to disk, secrets could leak; use `mlock` mitigation (future)
3. **Spectre / Meltdown:** Microarchitectural side-channel attacks; constant-time code doesn't defend against these
4. **Malware with Code Execution:** If malware runs during unlocking, it can capture the master password or plaintext passwords
5. **File System Metadata:** The vault file's creation/modification timestamps leak information about when secrets were added; not encrypted

---

## Summary: The One-Sentence Threat Model

**VaultKeep protects encrypted credentials stored on disk against an attacker who has obtained the vault file but not the master password, using modern authenticated encryption and memory-safe practices. It does not protect against malware, OS-level compromise, or physical seizure with threats/torture.**