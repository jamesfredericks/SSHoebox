# SSHoebox — Secure SSH & SFTP Manager

SSHoebox is a secure, native macOS application for managing SSH and SFTP connections. It stores credentials in a hardened encrypted vault, provides an embedded terminal with tab support and theme customization, and includes a built-in SFTP file browser, SSH agent, password generator, and backup tools.

## Features

### Secure Vault
- AES-256-GCM authenticated encryption for all sensitive data
- Master password protection with PBKDF2-HMAC-SHA256 (100k iterations)
- SQLCipher full-file encrypted database, with sensitive fields (credentials, hostnames, host options, snippets) encrypted again inside it
- **Touch ID / Face ID unlock**: the vault key is kept in the login keychain and only read after a Touch ID prompt (ad-hoc signed builds can't use Secure Enclave-bound keychain items)
- **Portable Vault and Sync**: cryptographic metadata lives in a sidecar `vault_metadata.json`; Macs can sync through iCloud Drive, Dropbox or OneDrive with record-level merging
- **Auto-lock**: configurable idle timeout locks the vault; active SSH sessions can delay the lock
- **Rate limiting**: exponential backoff after 5 failed unlock attempts (up to 5 minutes)
- **Password history**: previous secrets are archived when a credential changes

### Connecting Quickly
- **Quick Connect (⌘K)**: type part of a host's name, address, user or `#tag`; Return opens a terminal, ⇧Return a new tab, ⌘Return its files. Also in the toolbar and the menu bar icon
- **`ssh://` links** open the matching saved host, or a New Host sheet filled in from the link (Preferences can make SSHoebox the `ssh://` handler)
- **Favorites and tags**: pin hosts to a Favorites section and label them; search matches tags
- Host context menu: open terminal, new tab, files, favorite, edit, **duplicate** (with credentials), copy `ssh://` link, delete
- Groups, host search and "last connected" times

### Connections
- **Jump hosts (`ssh -J`)**: reach a host through another saved host, which uses its own credential; chains of jump hosts work too, and failures name the hop that failed
- **Keep-alives** (`ServerAliveInterval`): every 30 s by default, per host or off; a connection that stops answering is closed so you can reconnect
- **Tunnels (`ssh -L`)**: local port forwards per host, opened with the terminal session or started from its tunnels menu
- **Startup command**: typed into the shell when a terminal opens (e.g. `sudo -i`)
- **Stored keys**: Ed25519, ECDSA (P-256/384/521) and RSA, in OpenSSH (including passphrase-protected), PKCS#1, SEC1 or PKCS#8 form. RSA logs in as `rsa-sha2-512`/`rsa-sha2-256`, never SHA-1, so it works with OpenSSH 8.8+
- Password, keyboard-interactive (one-time codes, YubiKey) and external agent keys (Bitwarden, 1Password)
- **Install Public Key on Server** (like `ssh-copy-id`): adds a stored or agent key's public half to `~/.ssh/authorized_keys`, logging in with the server's saved credential or an open session
- **Import from `~/.ssh/config`**, including `ProxyJump`, `LocalForward` and `ServerAliveInterval`; or from CSV / Bitwarden
- **TOFU host key verification** with a known-hosts store; key changes are refused
- **Login log** (Settings → Logs, ⌥⌘L) with `ssh -v`-style detail for every login attempt; secrets are never logged

### Embedded Terminal
- Tabs per host; the screen and scrollback survive navigating away and back
- **Split** a host's sessions side by side, or see every open session from all hosts in the **Sessions** workspace
- **Broadcast input**: sessions in the broadcast group all receive what you type (per session, per host, or all), with clear orange markings; the workspace can also send one line to the group
- **Snippets**: saved commands per host or for all hosts, run from the tab bar (⌥-click types without running)
- **Find** in the terminal (⌘F, ⌘G, ⇧⌘G)
- **Session recording**: a transcript of what the session showed, per session or for all sessions (Preferences), **encrypted at rest** (AES-256-GCM, key derived from the vault key; not even the host name is visible in the files) and read in Settings → Recordings
- Reconnect overlay with the failure reason, adjustable font size (⌘+/⌘−), themes
- OSC 52 clipboard writes only when allowed in Preferences; terminal links open only http(s) URLs

### SFTP File Browser
- Breadcrumb navigation, multi-select, show/hide dotfiles
- Upload and download **files and whole folders**, by button, context menu or **drag and drop**; streamed with progress, cancellable, never overwriting a local file
- Create folders, rename, delete (folders with their contents, after confirming), copy paths
- Works through jump hosts and shares the host key store with the terminal

### SSH Agent
- Built-in OpenSSH-compatible SSH agent (Unix socket at `~/.config/com.sshoebox.app/agent.sock`)
- Serves vault key credentials while the vault is unlocked, with RSA SHA-2 signatures
- Auto-starts on unlock; stops on lock

### Tools
- **Password Generator**: random passwords or passphrases; configurable length, character sets, separators
- **SSH key generation**: Ed25519 key pairs saved as credentials
- **Backup & Restore**: export the vault to a single encrypted `.abgvault` file
- **Clipboard auto-clear** for copied secrets

## Installation

### Build from Source

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

> **SQLCipher is bundled automatically.** The script embeds `SQLCipher.framework` into the app bundle — no manual steps needed.

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
- All credential decryption is on-demand; secrets are never written to disk in plaintext. Session recordings are encrypted as they're written and only decrypted in memory to view them (exporting one as text is an explicit, warned action)
- Field-level AES-256-GCM encryption is applied on top of SQLCipher full-file encryption (defense in depth)
- The SSH agent only serves keys while the vault is unlocked

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a pull request.
