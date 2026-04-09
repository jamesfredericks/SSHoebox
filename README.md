# SSHoebox — Secure SSH & SFTP Manager

SSHoebox is a secure, native macOS application for managing SSH and SFTP connections. It stores credentials in a hardened encrypted vault, provides an embedded terminal with tab support and theme customization, and includes a built-in SFTP file browser, SSH agent, password generator, and backup tools.

## Features

### Secure Vault
- AES-256-GCM authenticated encryption for all sensitive data
- Master password protection with PBKDF2-HMAC-SHA256 (100k iterations)
- SQLCipher full-file encrypted database
- **Touch ID / Face ID unlock** — biometric access via Secure Enclave-backed keychain item
- **Portable Vault** — cryptographic metadata lives in a sidecar `vault_metadata.json`, making it trivial to sync your vault across Macs via iCloud Drive, Dropbox, or any other provider
- **Auto-lock** — configurable idle timeout locks the vault automatically; active SSH sessions delay lock
- **Rate limiting** — exponential backoff after 5 failed unlock attempts (up to 5-minute lockout)
- **Password history** — previous secrets are archived when a credential is updated, reviewable and copyable at any time

### Connection Manager
- Organize hosts into collapsible groups; store passwords and SSH private keys per host
- **Host search** — instant filtering across host name, hostname, and username
- **Connection history** — each host card shows when you last connected (e.g. "2 hours ago")
- **TOFU host key verification** — trust-on-first-use fingerprints stored in a local known-hosts database; detects key changes and alerts you
- One-click SSH and SFTP connection launching
- **Clipboard auto-clear** — copied secrets are cleared from the clipboard after a configurable delay (default 30 s); an in-app badge counts down and offers a manual clear
- **SSH key generation** — generate Ed25519 key pairs in-app; private key saved as a credential, public key ready to copy to your server
- **Import from ~/.ssh/config** — parse your existing SSH config and import selected hosts in one click
- **Import from CSV or Bitwarden** — bulk-import hosts and passwords from a CSV file or a Bitwarden JSON export

### Embedded Terminal
- Fully functional embedded remote terminal (`SwiftTerm` + `Citadel`)
- Multi-tab support — open multiple sessions to the same host simultaneously
- **Zero-disk security** — all authentication is handled in-memory; no plaintext passwords or scripts ever touch disk
- Automatic reconnect overlay when a session drops
- Customizable themes (Matrix, Ocean, Sunset, Deep Space, Nature, Glacier)
- Supports password auth, Ed25519 key auth, RSA key auth, and keyboard-interactive (YubiKey / MFA)
- **Encrypted key passphrase support** — passphrase-protected private keys prompt inline without exposing the passphrase
- **Adjustable font size** — `⌘+` / `⌘−` keyboard shortcuts, +/− buttons in the tab bar, or the Preferences stepper

### SFTP File Browser
- Full file browser with breadcrumb path navigation
- Upload files from your Mac; download files with a native Save panel
- Create folders, rename entries, delete files and directories
- Show/hide dotfiles toggle
- Shares the same TOFU host key store as the SSH terminal

### SSH Agent
- Built-in OpenSSH-compatible SSH agent (Unix socket at `~/.config/com.sshoebox.app/agent.sock`)
- Serves all vault key credentials automatically when the vault is unlocked
- Full RSA SHA-2 support (`rsa-sha2-256`, `rsa-sha2-512`) — compatible with OpenSSH 8.8+
- Auto-starts on unlock; stops on lock

### Menu Bar
- Persistent menu bar icon shows vault status at a glance
- Displays active session count when connections are open
- Quick actions: open the main window, lock the vault, or quit

### Tools
- **Password Generator** — random passwords or passphrases (Bitwarden-style); configurable length, character sets, separators, and ambiguous-character avoidance
- **Backup & Restore** — export the entire vault to a single encrypted `.abgvault` file; import on any Mac

## Installation

### Option 1: Build from Source (recommended)

Building from source avoids Gatekeeper restrictions entirely and guarantees Touch ID works out of the box.

**Requirements:** macOS 14.0 (Sonoma) or later, Swift toolchain (`xcode-select --install`)

```bash
git clone https://github.com/jamesfredericks/SSHoebox.git
cd SSHoebox

# Build and package
./scripts/bundle_app.sh

# Install
sudo cp -r dist/SSHoebox.app /Applications/
```

### Option 2: Pre-built Binary

1. Download the latest `SSHoebox-v2.3.0.zip` from [Releases](https://github.com/jamesfredericks/SSHoebox/releases)
2. Unzip and move `SSHoebox.app` to `/Applications`
3. Remove the quarantine flag (required for ad-hoc–signed binaries):
   ```bash
   sudo xattr -cr /Applications/SSHoebox.app
   ```
4. Launch `SSHoebox.app`

> **Why the extra command?** SSHoebox is signed with an ad-hoc certificate rather than a paid Apple Developer ID. The `xattr -cr` command removes the macOS quarantine flag placed on downloaded files — a standard workaround for open-source Mac apps distributed outside the App Store.

## First Run

1. On first launch you will be prompted to create a **Master Password**
2. This password encrypts your vault and **cannot be recovered if lost** — keep a copy somewhere safe
3. After your first successful unlock you'll be offered to enable **Touch ID / Face ID**
4. Add your first host and credential, then click **Connect**

> **SSH Agent:** To use SSHoebox as your system SSH agent, add the following to your shell profile:
> ```bash
> export SSH_AUTH_SOCK="$HOME/.config/com.sshoebox.app/agent.sock"
> ```
> The agent starts automatically when you unlock the vault (configurable in Preferences).

## Development

```bash
# Debug build
swift build

# Run tests
swift test

# Run a single test suite
swift test --filter CryptoTests

# Production bundle (creates signed .app in dist/)
./scripts/bundle_app.sh

# Open in Xcode
open Package.swift
```

## Architecture

The codebase is split into two Swift package targets:

- **`SSHoeboxCore`** — pure business logic with no UI dependencies. Security, storage, SSH, SFTP, agent, and backup logic all live here.
- **`SSHoeboxApp`** — SwiftUI application (MVVM). Views are thin; ViewModels own domain logic.

**Key security properties:**
- Master password is never stored — only the derived vault key (in memory) and a biometric-gated keychain item
- All credential decryption is on-demand; secrets are never written to disk in plaintext
- Field-level AES-256-GCM encryption is applied on top of SQLCipher full-file encryption (defense in depth)
- The SSH agent only serves keys while the vault is unlocked

## License

Copyright © 2026. All rights reserved.

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a pull request.
