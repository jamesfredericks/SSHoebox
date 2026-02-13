# Secure SSH + FTP Manager for macOS — Architecture & Design (v1)

## 1) Purpose
Build a **macOS utility app** that securely stores and manages **SSH and FTP/SFTP endpoints** (host/port/protocol) with **associated credentials** (username/password and optionally private keys), offers **password history**, a **Bitwarden-like password generator**, **encrypted local storage**, **easy backups**, **end-to-end encrypted cloud backup**, and an optional **customizable embedded shell** with themes.

This document is written so an AI/dev can implement the app with clear boundaries, security decisions, and component responsibilities.

---

## 2) Goals and Non-Goals

### Goals
- Store SSH and FTP/SFTP endpoints with credentials securely.
- Local database stored on disk with **AES-256 authenticated encryption**.
- Master password protected vault with strong key derivation.
- Backup/restore: simple one-file export/import.
- Password history per credential with timestamps and rotation notes.
- Password generator comparable to Bitwarden (length, character sets, avoid ambiguous chars, passphrases, etc.).
- Optional secure cloud backup that is **encrypted before upload** (server cannot decrypt).
- Customizable embedded shell UI with themes (optional).

### Non-Goals (v1)
- Acting as a full replacement for dedicated password managers (Bitwarden/1Password).
- Multi-device real-time sync with complex merge UI (can be incremental).
- Remote “agent” install on servers or privileged credential injection into system keychains beyond app scope.

---

## 3) Platform & Tech Stack

### macOS App
- **Language/UI**: Swift + SwiftUI (preferred), AppKit bridging where needed.
- **Crypto**: Apple CryptoKit for primitives + audited implementations for KDF if needed.
- **Secure storage**:
  - Master key material protected with **Keychain** + user master password.
  - Encrypted DB file stored in `Application Support/<bundle-id>/vault.db`.
- **Networking**:
  - Cloud backup: URLSession.
  - SSH: prefer **libssh2** wrapper OR a Swift SSH library (choose based on maturity).
  - FTP/SFTP: strongly prefer **SFTP**; FTP can be supported but discouraged (plaintext by design). FTPS optional later.

### Recommended Packaging
- Sandboxed app (Mac App Store compatible if desired) with hardened runtime.
- Code signing + notarization.

---

## 4) High-Level System Overview

### Modules
1. **UI Layer**
   - Vault unlock/onboarding
   - Host/credential management
   - Password generator
   - Backup/restore
   - Cloud backup settings
   - Shell/terminal (optional)

2. **Domain Layer**
   - Models: Host, Credential, Secret, PasswordHistory, Tag, Folder, ConnectionProfile
   - Use-cases: Add/Edit/Delete, Search, GeneratePassword, RotatePassword, ExportVault, ImportVault, CloudBackupPush/Pull

3. **Security & Crypto Layer**
   - Master password KDF
   - Key hierarchy (vault key, record keys)
   - Encrypt/decrypt APIs
   - Secure wipe strategies (best-effort; OS-level constraints apply)

4. **Storage Layer**
   - Encrypted database file (SQLite) with encrypted fields or full-file encryption
   - Repository interfaces
   - Migration framework

5. **Sync/Backup Layer**
   - Local export/import format
   - Cloud backup upload/download (encrypted blobs)
   - Optional versioning and conflict detection

6. **Connection Layer**
   - SSH connect (host key verification, known_hosts management)
   - FTP/SFTP connect
   - Session logging (no secret logging)
   - Optional: command templates/snippets

7. **Shell/Theming Layer (Optional)**
   - Embedded terminal view via PTY
   - Theme packs (colors/fonts/prompt templates)
   - Profile-specific environment variables (no secrets in env by default)

---

## 5) Core Security Design

### 5.1 Threat Model (practical)
**Protect against:**
- Offline theft of the vault file.
- Malware reading plaintext secrets from disk.
- Cloud provider compromise (cloud backup should be unreadable).
- Accidental secret exposure through logs/crashes.

**Not fully protect against:**
- A fully compromised running machine/user session (keylogging, memory scraping).
- A malicious admin with system-level access while vault is unlocked.

### 5.2 Key Hierarchy
- User sets **Master Password** (never stored).
- Derive a **Master Key** via strong KDF:
  - Preferred: **Argon2id** (memory-hard). If not feasible, PBKDF2-HMAC-SHA256 with high iterations.
- From Master Key derive:
  - **Vault Encryption Key (VEK)** for DB/file encryption.
  - **Vault MAC/AEAD key** (if using separate).
- Optionally derive **Record Keys**:
  - Each credential record encrypted with a per-record key derived from VEK + record UUID (limits blast radius).

### 5.3 Encryption Choices
- Use **AES-256-GCM** (AEAD) or **ChaCha20-Poly1305** (AEAD).
- Always store:
  - `salt` (for KDF)
  - `nonce` per encryption
  - `ciphertext`
  - `auth tag` (implicit with AEAD)
- Never reuse nonces for the same key.

### 5.4 Key Storage
- Store only:
  - KDF parameters + salt (safe to store)
  - An encrypted “keycheck” blob to verify password without decrypting everything.
- When user unlocks:
  - Master password → KDF → Master Key → VEK
- Use **Keychain** to store:
  - Optional “quick unlock” token protected by biometrics (Touch ID) and Secure Enclave policies (if desired).
  - Never store master password.

### 5.5 Memory/Logging Hygiene
- Mark secret fields as sensitive; do not print them.
- Avoid writing secrets to crash reports.
- Consider short-lived decrypted objects; decrypt-on-demand.

---

## 6) Storage Architecture (Local Encrypted DB)

### Option A (Preferred): SQLCipher
- SQLite database encrypted at rest (AES-256).
- Pros: proven pattern, simpler query model.
- Cons: dependency + build steps.

### Option B: SQLite + Encrypted Columns
- Keep SQLite plaintext structure, encrypt sensitive fields (passwords, notes, private keys).
- Pros: less dependency.
- Cons: metadata leakage (record counts, names unless encrypted), more DIY crypto handling.

**Recommendation**: Start with **SQLCipher** for full-file encryption + also encrypt especially sensitive fields as defense-in-depth if practical.

### Data Model (minimal)
- `hosts`
  - `id (uuid)`, `name`, `hostname`, `port`, `protocol (ssh|sftp|ftp)`, `tags`, `created_at`, `updated_at`
- `credentials`
  - `id`, `host_id`, `username`, `secret_blob` (AEAD encrypted), `type (password|key)`, `created_at`, `updated_at`
- `password_history`
  - `id`, `credential_id`, `secret_blob` (encrypted), `changed_at`, `note`
- `known_hosts`
  - `id`, `hostname`, `port`, `fingerprint`, `algo`, `first_seen_at`, `last_seen_at`, `trust (trusted|untrusted|changed)`
- `settings`
  - `id`, `cloud_provider`, `cloud_endpoint`, `cloud_last_backup`, `theme_profile`, etc.

**Encrypted blob format** (suggested JSON or binary):
- `version`
- `nonce`
- `ciphertext`
- `tag`
- `aad` (optional associated data such as record id)

---

## 7) Backups

### 7.1 Local Backup (Easy Export/Import)
- Export a single file: `VaultBackup.abgvault` (name arbitrary)
- Contents:
  - Header: format version, KDF params, salt
  - Encrypted payload: the entire DB dump OR DB file bytes
  - Optional: checksum of ciphertext (non-secret integrity)
- Export should never require plaintext on disk:
  - Stream encrypt payload to output file.

### 7.2 Restore Flow
- User selects backup file
- Prompt master password
- Validate via keycheck
- Decrypt into new vault DB (atomic write)
- Run migrations if format version older

---

## 8) Secure Cloud Backup (End-to-End Encrypted)

### 8.1 Principle
Cloud sees only ciphertext. Decryption keys never leave device.

### 8.2 Minimal Viable Design (v1)
- Cloud provider options:
  - **WebDAV**, S3-compatible, or a simple HTTPS endpoint.
- Upload encrypted backup blob:
  - `backup_latest.bin`
  - `backup_<timestamp>.bin` (optional rotation)
- Store remote metadata:
  - last backup time, last backup hash, version.

### 8.3 Versioning & Conflicts (simple)
- Each backup includes:
  - `vault_id`
  - `device_id`
  - `backup_sequence` or timestamp
- On download, if remote is newer than local and local has changes since last sync:
  - show “choose remote/local” (v1)
  - later: merge tools.

### 8.4 Authentication
- OAuth token / API key stored in Keychain.
- Rotate tokens and support revocation.

---

## 9) Password Generator (Bitwarden-like)

### Modes
1. **Random Password**
   - Length (e.g., 8–128)
   - Include: lowercase/uppercase/digits/symbols
   - Min counts per group (optional)
   - Avoid ambiguous characters (O/0, l/1, etc.)
   - Option to require at least one of each selected set
2. **Passphrase**
   - Word count (e.g., 3–10)
   - Separator (space, -, _)
   - Capitalize option
   - Include number option
3. **Username Generator** (optional)
   - Email-like or random string

### Entropy Guidance
- Display estimated strength (bits) and common policy warnings.
- Never log generated values.

---

## 10) Password History & Rotation
- Every time credential secret changes:
  - Move previous secret into `password_history` with timestamp and optional note.
- Provide UI:
  - “View history” (requires re-auth/unlock if app supports partial lock)
  - “Copy previous” (warn user)
  - “Rotate” workflow:
    - generate new password
    - copy to clipboard
    - user updates remote system
    - confirm success → save new secret and write history

---

## 11) SSH / FTP(SFTP) Connection Management

### 11.1 SSH Requirements
- Host key verification:
  - Maintain `known_hosts` store
  - First-connect prompt: trust fingerprint (TOFU)
  - Detect changes and warn strongly
- Support:
  - Username/password auth
  - Optional private key auth (encrypted at rest)
- Session handling:
  - No secrets written to session logs
  - Timeouts + safe error messages

### 11.2 FTP/SFTP Notes
- Prefer **SFTP** (over SSH) for security.
- If FTP is supported:
  - Show warnings: FTP is plaintext and unsafe on untrusted networks.
  - Encourage FTPS/SFTP.

---

## 12) Embedded Shell with Themes (Optional)

### Design
- Provide a “Shell” tab with:
  - Profiles (per host or global)
  - Theme selection (color palette, font, prompt style)
- Implementation approach:
  - Spawn local shell via PTY (zsh/bash)
  - Provide “Connect to host” actions:
    - Use OS `ssh` binary with safe argument passing OR library-based SSH session.
- Secret handling:
  - Never inject passwords directly into terminal input by default.
  - Prefer key-based auth or user paste from clipboard.
  - Optionally provide a “one-time paste” helper with warnings.

### Theme Packs
- Stored as JSON:
  - background/foreground colors
  - ANSI palette mapping
  - font family/size
  - prompt templates (non-sensitive)

---

## 13) UX Flows (Minimal)

### Onboarding
1. Create Vault
2. Set Master Password + confirm
3. Optional: enable Touch ID unlock
4. Create first host + credential

### Daily Use
- Unlock vault → list/search hosts → open details
- Copy username/password (clipboard auto-clear option)
- Generate password → rotate workflow
- Backup now / schedule backup (optional later)

### Backup
- Local: Export file → save location
- Cloud: “Enable cloud backup” → sign in → backup now

---

## 14) Security Controls Checklist
- [ ] AEAD encryption with unique nonces
- [ ] Strong KDF with stored parameters
- [ ] Keychain for tokens/biometric unlock handles
- [ ] Clipboard auto-clear timer + “sensitive clipboard” warnings
- [ ] No plaintext secrets in logs
- [ ] Host key verification and fingerprint warnings
- [ ] Database file permissions restricted to user
- [ ] Hardened runtime, signed builds
- [ ] Dependency audit (SSH libs, SQLCipher)

---

## 15) Project Structure (Suggested)
- `App/` SwiftUI views, navigation, state
- `Core/Domain/` models + use-cases
- `Core/Security/` crypto, KDF, keychain, secure primitives
- `Core/Storage/` repositories, migrations, db layer
- `Core/Backup/` export/import, cloud providers
- `Core/Connections/` SSH/SFTP/FTP session managers
- `Core/Shell/` terminal view + theming (optional)
- `Tests/` unit tests + crypto test vectors + integration tests

---

## 16) Testing Strategy
- Unit tests:
  - KDF parameter handling, encryption/decryption round-trip
  - Record-level encryption with AAD
  - Backup export/import correctness
- Integration tests:
  - DB migrations
  - Cloud backup upload/download (mock server)
- Security tests:
  - Ensure no secrets appear in logs
  - Ensure vault cannot be opened with wrong password
  - Ensure host key change detection works

---

## 17) Future Enhancements (Post-v1)
- Full multi-device sync with merge UI
- SSH agent integration and key forwarding controls
- TOTP storage (carefully scoped)
- Policy templates per org/team
- CLI companion tool that reads vault via secure IPC (no disk secrets)

---

## 18) Implementation Notes for an AI Builder
- Always implement crypto via well-reviewed primitives (CryptoKit + vetted KDF).
- Treat secrets as “sensitive data” end-to-end: UI masking, logging discipline, clipboard safety.
- Start with local vault + export/import before adding cloud.
- Make SFTP first-class; treat FTP as legacy with warnings.
- Keep formats versioned (`vault_format_version`, `backup_format_version`) for migration safety.
