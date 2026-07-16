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
   - **Cost:** ~0.5–1.0 second per guess on modern hardware; 100,000 guesses would take ~1.4 days on a single CPU core
   - **Residual Risk:** Weak master passwords (< 12 chars, no mixed case/symbols) can be cracked faster; user education required

3. **Plaintext Password Exposure During Use**
   - Attacker with code execution while the app runs could intercept passwords in memory
   - **Defense:** All secrets wrapped in `zeroize`-friendly types; master password and decrypted vault contents cleared from memory immediately after use; no logging of plaintext passwords
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

3. **Vault File Tampering (v1)**
   - Attacker modifies the encrypted vault file, hoping to trick the app into leaking secrets or crashing in a way that exposes data
   - **Defense (added based on IACR 2026 research):** AEAD (Authenticated Encryption with Associated Data) ensures that any tampering with the ciphertext is detected; we bind the vault ID and item ID to the authentication tag so swapping items between vaults is impossible
   - **Status:** Partially in scope; we validate AEAD tags, but don't have a vault-wide integrity commitment yet (Phase 2)

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
- **Output:** 256-bit master key used to wrap the data key

### Encryption

- **Primary Cipher:** AES-256-GCM
  - 256-bit key, 96-bit nonce (random), 128-bit authentication tag
  - NIST FIPS 197 approved; hardware-accelerated on modern CPUs
- **Fallback Cipher:** ChaCha20-Poly1305 (for systems without AES-NI)
  - XChaCha20-Poly1305 variant (192-bit nonce) for long-lived keys
  - IETF RFC 7539 approved; constant-time on all CPUs

### Integrity & Binding

- **AEAD Binding:** vault_id || item_id included as Associated Data (AAD) in every encryption
  - Prevents cut-and-paste attacks between items or vaults
  - Tag is verified before any decryption attempt

### Memory Management

- All secrets (master password, derived keys, plaintext passwords) wrapped in zeroizable types
- On-drop, buffers are overwritten with zeros before deallocation
- No `String` types for secrets; `bytes` + `Zeroizing` wrappers only

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

1. **Cipher Agility:** Header byte for cipher ID (1 = AES-256-GCM, 2 = ChaCha20-Poly1305, 3 = reserved for future)
2. **KDF Agility:** Header byte for KDF ID (1 = Argon2id, 2 = PBKDF2-HMAC-SHA256 for FIPS-only builds)
3. **KEK Interface:** `KeyEncryptionKey` trait with `wrap()` / `unwrap()` methods; default impl = Argon2id; can be swapped for AWS KMS, GCP KMS, TPM, Secure Enclave
4. **Algorithm Upgrades:** Vault version field in header allows migration path if we need to deprecate old ciphers

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