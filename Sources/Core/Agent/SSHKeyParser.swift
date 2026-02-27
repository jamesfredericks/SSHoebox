import Foundation
import CryptoKit  // Curve25519, Insecure (SHA1/MD5 hashes)
import Citadel    // Adds Curve25519.Signing.PrivateKey(sshEd25519:), Insecure.RSA, RSA key types

/// Parses OpenSSH private keys and produces SSH agent wire-format blobs.
/// Supports Ed25519 and RSA key types.
///
/// This type lives in SSHoeboxCore so it can access Citadel's internal parsing
/// APIs without exposing them to the SSHoeboxApp layer.
public struct SSHKeyParser {

    public enum SSHKeyError: Error {
        case unsupportedKeyType
        case signingFailed
    }

    // MARK: - Public Key Blob

    /// Parses an OpenSSH PEM private key string and returns the SSH wire-format
    /// public key blob expected by the SSH agent protocol.
    ///
    /// Wire format: `uint32(algo_len) + algo_string + key_data`
    ///
    /// - Ed25519: `"ssh-ed25519" + uint32(32) + raw_public_key_bytes`
    /// - RSA:     `"ssh-rsa" + e_mpint + n_mpint`
    public static func publicKeyBlob(fromPEM pem: String) throws -> Data {
        // Try Ed25519 first (most common modern key type)
        if let edKey = try? Curve25519.Signing.PrivateKey(sshEd25519: pem) {
            return ed25519PublicKeyBlob(edKey.publicKey)
        }

        // Fall back to RSA
        if let rsaKey = try? Insecure.RSA.PrivateKey(sshRsa: pem),
           let rsaPublicKey = rsaKey.publicKey as? Insecure.RSA.PublicKey {
            return rsaPublicKeyBlob(rsaPublicKey)
        }

        throw SSHKeyError.unsupportedKeyType
    }

    /// Returns true when `blob` matches the public key blob derived from `pem`.
    public static func publicKeyBlobMatches(blob: Data, pem: String) -> Bool {
        guard let keyBlob = try? publicKeyBlob(fromPEM: pem) else { return false }
        return keyBlob == blob
    }

    // MARK: - Signing

    /// Signs `data` with the private key contained in `pem` and returns an SSH
    /// agent-protocol signature blob.
    ///
    /// Signature blob format (the full blob, without an outer length prefix):
    /// `uint32(algo_len) + algo_string + uint32(sig_len) + sig_bytes`
    ///
    /// - Note: RSA signatures use SHA-1 (ssh-rsa), which is the baseline
    ///   algorithm mandated by the SSH agent protocol spec. Modern servers
    ///   prefer rsa-sha2-256 / rsa-sha2-512; that can be added later via flags.
    public static func sign(pem: String, data: Data) throws -> Data {
        // Ed25519
        if let edKey = try? Curve25519.Signing.PrivateKey(sshEd25519: pem) {
            let sig = try edKey.signature(for: data)
            return signatureBlob(algorithm: "ssh-ed25519", sigBytes: Data(sig))
        }

        // RSA (SHA-1)
        if let rsaKey = try? Insecure.RSA.PrivateKey(sshRsa: pem) {
            let sig = try rsaKey.signature(for: data) as Insecure.RSA.Signature
            return signatureBlob(algorithm: "ssh-rsa", sigBytes: sig.rawRepresentation)
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
