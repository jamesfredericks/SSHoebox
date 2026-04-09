# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SSHoebox is a native macOS SSH/SFTP connection manager with an encrypted credential vault. Built entirely in Swift/SwiftUI targeting macOS 14.0+. Not sandboxed; distributed as a signed `.app` ZIP.

## Commands

```bash
# Debug build
swift build

# Release build
swift build -c release --disable-sandbox

# Run tests
swift test

# Run a single test (e.g., CryptoTests)
swift test --filter CryptoTests

# Production bundle (creates signed .app in dist/)
./scripts/bundle_app.sh

# Open in Xcode
open Package.swift
```

## Architecture

The codebase is split into two Swift package targets:

- **`SSHoeboxCore`** — pure business logic, no UI dependencies. All security, storage, SSH, and backup logic lives here.
- **`SSHoeboxApp`** — SwiftUI application that depends on Core. MVVM pattern: ViewModels own domain logic, Views are thin.

### Layered Structure

```
SSHoeboxApp (SwiftUI Views + ViewModels)
    └── SSHoeboxCore
          ├── Domain/       — Data models (SavedHost, Credential, HostGroup)
          ├── Security/     — CryptoManager, KeychainManager, BiometricAuthManager, PasswordGenerator, IdleMonitor
          ├── Storage/      — DatabaseManager (SQLCipher + GRDB), HostRepository, CredentialRepository, GroupRepository
          ├── SSH/          — SSHSessionManager (Citadel wrapper, PTY, auth)
          ├── Shell/        — ThemeManager (terminal color themes)
          ├── Backup/       — BackupManager (export/import with checksum validation)
          └── Agent/        — SSHAgentServer (Unix socket), SSHAgentHandler, SSHAgentProtocol, SSHKeyParser
```

### Security Model

- **Vault unlock**: Master password → PBKDF2-HMAC-SHA256 (100k iterations, 32-byte random salt) → 256-bit vault key
- **Vault metadata** (`vault_metadata.json`) is a portable sidecar file containing salt + AES-GCM–encrypted validation token. Separating metadata from the database enables cloud sync (iCloud, Dropbox, etc.)
- **Database**: SQLCipher full-file AES-256 encryption; opened with derived vault key
- **Field-level encryption**: Sensitive credential columns (passwords, keys, usernames) are additionally encrypted via AES-256-GCM inside the database
- **Biometric unlock**: Vault key stored in Keychain with Secure Enclave protection (Touch ID/Face ID)
- **In-memory auth**: Credentials are decrypted in-memory and passed directly to Citadel — no temp files or plaintext ever touches disk

### Data Model

```
vault.db (SQLCipher)
├── hostGroup (id, name, sortOrder, createdAt)
├── host (id, name, hostname, port, protocol, user, groupId, timestamps)
└── credential (id, hostId, username, type, encryptedBlob, isInteractive, timestamps)

vault_metadata.json (portable, cloud-syncable)
├── salt          — 32-byte random, base64
├── validation    — AES-GCM encrypted sentinel string
└── version       — for future metadata migrations
```

### Connection Flow

1. `VaultViewModel` holds the vault key after unlock
2. User selects host + credential → `VaultViewModel` decrypts credential blob using vault key
3. `SSHSessionManager.connect(host:credential:)` initiates Citadel SSH session with in-memory credentials
4. PTY allocated, SwiftTerm (`TerminalView`) renders I/O
5. `TerminalSessionStore` manages the set of open terminal tabs

### SSH Agent

- Unix socket at `~/.config/com.sshoebox.app/agent.sock`
- Full OpenSSH agent protocol (SSH_AGENT_* messages) handled by `SSHAgentHandler`
- Auto-starts when vault unlocks (if enabled in Preferences); stops on vault lock

### Key Dependencies

| Package | Purpose |
|---|---|
| GRDB.swift (6.29.3+) | SQLite ORM with SQLCipher |
| SwiftTerm | Terminal emulator UI |
| Citadel (local, `Vendor/`) | SSH client implementation |
| CryptoKit | PBKDF2, HMAC, AES-GCM (Apple framework) |
| LocalAuthentication | Touch ID / Face ID |

Citadel is vendored locally at `Vendor/Citadel/` rather than fetched from a package registry.

## Key Files

| File | Role |
|---|---|
| `Sources/Core/Security/CryptoManager.swift` | KDF, AES-256-GCM encrypt/decrypt |
| `Sources/Core/Storage/DatabaseManager.swift` | SQLCipher init, schema migrations (v1→v3) |
| `Sources/Core/SSH/SSHSessionManager.swift` | Citadel SSH wrapper, PTY, all auth methods |
| `Sources/Core/Agent/SSHAgentServer.swift` | Unix socket SSH agent server |
| `Sources/Core/Backup/BackupManager.swift` | Export/import with checksum validation |
| `Sources/SSHoeboxApp/ViewModels/VaultViewModel.swift` | Central app state: unlock, lock, biometrics, auto-lock, agent lifecycle |
| `Sources/SSHoeboxApp/ViewModels/TerminalSessionStore.swift` | Active terminal session/tab management |
| `Sources/SSHoeboxApp/DesignSystem.swift` | Shared colors, typography, style tokens |
| `buildplan.md` | Detailed architecture and design reference |
