import Foundation
import CryptoKit  // Curve25519, Insecure (SHA1/MD5 hashes)
import Citadel    // Adds Curve25519.Signing.PrivateKey(sshEd25519:), Insecure.RSA, RSA key types

/// Parses OpenSSH private keys and produces SSH agent wire-format blobs.
/// Supports Ed25519 and RSA key types.
///
/// This type lives in SSHoeboxCore so it can access Citadel's internal parsing
/// APIs without exposing them to the SSHoeboxApp layer.
public struct SSHKeyParser {

    public enum SSHKeyError: Error, LocalizedError {
        case unsupportedKeyType
        case signingFailed
        case passphraseRequired
        case incorrectPassphrase

        public var errorDescription: String? {
            switch self {
            case .unsupportedKeyType:   return "Unsupported key type"
            case .signingFailed:        return "Signing failed"
            case .passphraseRequired:   return "This private key is encrypted and requires a passphrase"
            case .incorrectPassphrase:  return "Incorrect passphrase"
            }
        }
    }

    // MARK: - Public Key Blob

    /// Parses an OpenSSH PEM private key string and returns the SSH wire-format
    /// public key blob expected by the SSH agent protocol.
    ///
    /// Wire format: `uint32(algo_len) + algo_string + key_data`
    ///
    /// - Ed25519: `"ssh-ed25519" + uint32(32) + raw_public_key_bytes`
    /// - RSA:     `"ssh-rsa" + e_mpint + n_mpint`
    /// Returns `true` if the OpenSSH private key at `pem` is encrypted (requires a passphrase).
    public static func isEncryptedKey(_ pem: String) -> Bool {
        var key = pem.replacingOccurrences(of: "\n", with: "")
        guard key.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"),
              key.hasSuffix("-----END OPENSSH PRIVATE KEY-----") else { return false }
        key.removeLast("-----END OPENSSH PRIVATE KEY-----".count)
        key.removeFirst("-----BEGIN OPENSSH PRIVATE KEY-----".count)
        guard let data = Data(base64Encoded: key) else { return false }

        // OpenSSH binary format: magic(15+1 bytes) + cipher_name (uint32 len + bytes)
        let magic = "openssh-key-v1\0"
        let magicCount = magic.utf8.count
        guard data.count > magicCount + 4 else { return false }
        let lenSlice = data[magicCount..<(magicCount + 4)]
        let cipherLen = Int(lenSlice.reduce(0 as UInt32) { ($0 << 8) | UInt32($1) })
        let nameStart = magicCount + 4
        guard nameStart + cipherLen <= data.count else { return false }
        let cipherName = String(data: data[nameStart..<(nameStart + cipherLen)], encoding: .utf8) ?? "none"
        return cipherName != "none"
    }

    public static func publicKeyBlob(fromPEM pem: String, passphrase: String? = nil) throws -> Data {
        let decryptionKey = passphrase.flatMap { $0.data(using: .utf8) }

        // Try Ed25519 first (most common modern key type)
        if let edKey = try? Curve25519.Signing.PrivateKey(sshEd25519: pem, decryptionKey: decryptionKey) {
            return ed25519PublicKeyBlob(edKey.publicKey)
        }

        // Fall back to RSA
        if let rsaKey = try? Insecure.RSA.PrivateKey(sshRsa: pem, decryptionKey: decryptionKey),
           let rsaPublicKey = rsaKey.publicKey as? Insecure.RSA.PublicKey {
            return rsaPublicKeyBlob(rsaPublicKey)
        }

        // Check if encrypted key needs a passphrase
        if isEncryptedKey(pem) {
            throw passphrase == nil ? SSHKeyError.passphraseRequired : SSHKeyError.incorrectPassphrase
        }

        throw SSHKeyError.unsupportedKeyType
    }

    /// Returns true when `blob` matches the public key blob derived from `pem`.
    public static func publicKeyBlobMatches(blob: Data, pem: String) -> Bool {
        guard let keyBlob = try? publicKeyBlob(fromPEM: pem) else { return false }
        return keyBlob == blob
    }

    // MARK: - Signing

    /// Signs `data` with the private key in `pem` and returns an SSH agent-protocol
    /// signature blob: `uint32(algo_len) + algo_string + uint32(sig_len) + sig_bytes`
    ///
    /// `flags` follows the OpenSSH agent protocol (ssh-agent.h):
    /// - `0x02` (`SSH_AGENT_RSA_SHA2_256`) → `rsa-sha2-256` (RFC 8332)
    /// - `0x04` (`SSH_AGENT_RSA_SHA2_512`) → `rsa-sha2-512` (RFC 8332)
    /// - `0`    (default)                  → `ssh-rsa` (SHA-1, legacy fallback)
    /// Ed25519 always uses `ssh-ed25519` regardless of flags.
    public static func sign(pem: String, data: Data, flags: UInt32 = 0, passphrase: String? = nil) throws -> Data {
        let decryptionKey = passphrase.flatMap { $0.data(using: .utf8) }

        // Ed25519 — flags are ignored; only one algorithm exists
        if let edKey = try? Curve25519.Signing.PrivateKey(sshEd25519: pem, decryptionKey: decryptionKey) {
            let sig = try edKey.signature(for: data)
            return signatureBlob(algorithm: "ssh-ed25519", sigBytes: Data(sig))
        }

        // RSA — honour the flags for SHA-256/512; fall back to SHA-1
        if let rsaKey = try? Insecure.RSA.PrivateKey(sshRsa: pem, decryptionKey: decryptionKey) {
            if flags & 0x04 != 0 {
                let sig = try rsaKey.signatureSHA512(for: data)
                return signatureBlob(algorithm: "rsa-sha2-512", sigBytes: sig.rawRepresentation)
            } else if flags & 0x02 != 0 {
                let sig = try rsaKey.signatureSHA256(for: data)
                return signatureBlob(algorithm: "rsa-sha2-256", sigBytes: sig.rawRepresentation)
            } else {
                let sig = try rsaKey.signature(for: data) as Insecure.RSA.Signature
                return signatureBlob(algorithm: "ssh-rsa", sigBytes: sig.rawRepresentation)
            }
        }

        if isEncryptedKey(pem) {
            throw passphrase == nil ? SSHKeyError.passphraseRequired : SSHKeyError.incorrectPassphrase
        }

        throw SSHKeyError.unsupportedKeyType
    }

    // MARK: - Private: Public key blob builders

    private static func ed25519PublicKeyBlob(_ key: Curve25519.Signing.PublicKey) -> Data {
        var out = Data()
        appendSSHString("ssh-ed25519", to: &out)
        appendSSHData(key.rawRepresentation, to: &out)
        return out
    }

    private static func rsaPublicKeyBlob(_ key: Insecure.RSA.PublicKey) -> Data {
        // rawRepresentation = e_mpint + n_mpint (already SSH-encoded by Citadel)
        var out = Data()
        appendSSHString("ssh-rsa", to: &out)
        out.append(key.rawRepresentation)
        return out
    }

    // MARK: - Private: Signature blob builder

    private static func signatureBlob(algorithm: String, sigBytes: Data) -> Data {
        var out = Data()
        appendSSHString(algorithm, to: &out)
        appendSSHData(sigBytes, to: &out)
        return out
    }

    // MARK: - Private: SSH binary encoding helpers

    /// Appends a UTF-8 string as an SSH string (uint32 length + bytes).
    private static func appendSSHString(_ string: String, to data: inout Data) {
        appendSSHData(Data(string.utf8), to: &data)
    }

    /// Appends arbitrary bytes as an SSH string (uint32 length + bytes).
    private static func appendSSHData(_ bytes: Data, to data: inout Data) {
        var bigEndianLength = UInt32(bytes.count).bigEndian
        withUnsafeBytes(of: &bigEndianLength) { data.append(contentsOf: $0) }
        data.append(bytes)
    }
}
