# SSHoebox - Secure SSH & SFTP Manager

SSHoebox is a secure, native macOS application for managing SSH and SFTP connections. It features a hardened vault for credentials, an embedded terminal with theme support, and built-in tools for password generation and backups.

## Features

- **Secure Vault**:
  - AES-256 authenticated encryption (GCM) for all sensitive data
  - Master Password protection with strong KDF (PBKDF2-HMAC-SHA256)
  - SQLCipher-based encrypted database storage
  - **Touch ID / Face ID unlock** — unlock your vault with a fingerprint instead of typing your master password
  
- **Connection Manager**:
  - Organize Hosts and Credentials (passwords, keys)
  - One-click connection launching for SSH and SFTP
  - "Copy to Clipboard" with auto-clear warnings (UI indicator)

- **Embedded Shell**:
  - Fully functional embedded local terminal (zsh/bash)
  - Customizable themes (Matrix, Ocean, Sunset, Deep Space)
  - Auto-injection of connection commands

- **Tools**:
  - **Password Generator**: Create strong, random passwords or passphrases (Bitwarden-style)
  - **Backup & Restore**: Securely export your entire vault for safe-keeping

## Installation

### Option 1: Download Pre-built App (Recommended)

1. Download the latest release from [Releases](https://github.com/jamesfredericks/SSHoebox/releases)
2. Unzip `SSHoebox-v1.2.0.zip`
3. Move `SSHoebox.app` to your `/Applications` folder
4. **First launch:** Right-click the app → **Open** → Click **"Open"** in the security dialog
5. Future launches can use double-click

> **Note:** macOS will show a security warning because this app is not notarized with Apple. This is normal for open-source apps distributed outside the App Store.

### Option 2: Build from Source

**Requirements:**
- macOS 14.0 (Sonoma) or later
- Xcode 15.0+ or Swift toolchain

**Steps:**

1. Clone the repository:
   ```bash
   git clone https://github.com/jamesfredericks/SSHoebox.git
   cd SSHoebox
   ```

2. Run using Swift Package Manager:
   ```bash
   swift run
   ```
   Or open `Package.swift` in Xcode and run the `SSHoebox` scheme.

3. **(Optional)** Build a standalone app:
   ```bash
   ./scripts/bundle_app.sh
   ```
   The app will be created in `dist/SSHoebox.app`

## First Run

1. On first launch, you will be prompted to create a **Master Password**
2. This password encrypts your vault and **cannot be recovered if lost**
3. After your first successful unlock, you'll be prompted to enable **Touch ID / Face ID** for faster access
4. Once unlocked, you can start adding Hosts and Credentials

> **Tip:** You can enable or disable biometric unlock at any time from **Preferences → Biometric Unlock**.

## Architecture

- **Core**: Contains all business logic, security primitives, and database management. Isolated from UI.
- **SSHoeboxApp**: The SwiftUI layer, following MVVM pattern.
- **Security**: Built on top of Apple's `CryptoKit` and `SQLCipher` for robust data protection.

## Development

### Building a Release

To create a distributable app bundle:

```bash
./scripts/bundle_app.sh
```

This will:
- Build the app in release mode
- Create a signed `.app` bundle
- Generate a distributable ZIP file in `dist/`

See [Distribution Guide](docs/DISTRIBUTION.md) for more details.

## Security

SSHoebox takes security seriously:
- All credentials are encrypted at rest using AES-256-GCM
- Master password is never stored, only a derived key
- Database is encrypted with SQLCipher
- Touch ID / Face ID unlock uses a biometric-gated keychain item — your vault key is never exposed without fingerprint confirmation
- No telemetry or external network requests

For security concerns, please see [SECURITY.md](SECURITY.md) (if you plan to add one).

## License

Copyright © 2026. All rights reserved.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
