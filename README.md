# SSHoebox - Secure SSH & FTP Manager

SSHoebox is a secure, native macOS application for managing SSH and SFTP connections. It features a hardened vault for credentials, an embedded terminal with theme support, and built-in tools for password generation and backups.

## Features

- **Secure Vault**:
  - AES-256 authenticated encryption (GCM) for all sensitive data.
  - Master Password protection with strong KDF (PBKDF2-HMAC-SHA256).
  - SQLCipher-based encrypted database storage.
  
- **Connection Manager**:
  - Organize Hosts and Credentials (passwords, keys).
  - One-click connection launching for SSH and SFTP.
  - "Copy to Clipboard" with auto-clear warnings (UI indicator).

- **Embedded Shell**:
  - Fully functional embedded local terminal (zsh/bash).
  - Customizable themes (Matrix, Ocean, Sunset).
  - Auto-injection of connection commands.

- **Tools**:
  - **Password Generator**: Create strong, random passwords or passphrases (Bitwarden-style).
  - **Backup & Restore**: Securely export your entire vault for safe-keeping.

## Installation & Usage

### Requirements
- macOS 14.0 or later.
- Xcode 15.0+ (for building).

### Running the App
1. Clone the repository.
2. Navigate to the package directory:
   ```bash
   cd SSHoebox
   ```
3. Run using Swift Package Manager:
   ```bash
   swift run
   ```
   Or open the `Package.swift` file in Xcode and run the `SSHoebox` scheme.

### First Run
1. On first launch, you will be prompted to create a **Master Password**. This password encrypts your vault and cannot be recovered if lost.
2. Once unlocked, you can start adding Hosts and Credentials.

## Architecture

- **Core**: Contains all business logic, security primitives, and database management. Isolated from UI.
- **SSHoeboxApp**: The SwiftUI layer, following MVVM pattern.
- **Security**: Built on top of Apple's `CryptoKit` and `SQLCipher` for robust data protection.

## License

Copyright © 2026. All rights reserved.
