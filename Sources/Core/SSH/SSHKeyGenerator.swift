import Foundation
import Crypto
import Citadel

/// Generates SSH key pairs and formats them as OpenSSH PEM strings.
public struct SSHKeyGenerator {

    public enum KeyType: String, CaseIterable {
        case ed25519 = "Ed25519"
    }

    public struct GeneratedKeyPair {
        public let privateKeyPEM: String
        public let publicKeyOpenSSH: String
        public let keyType: KeyType
        public let comment: String
    }

    /// Generate an Ed25519 key pair.
    /// - Returns: OpenSSH PEM private key and OpenSSH public key string (`ssh-ed25519 AAAA… comment`).
    public static func generateEd25519(comment: String = "") throws -> GeneratedKeyPair {
        let privateKey = Curve25519.Signing.PrivateKey()
        let privatePEM = privateKey.makeSSHRepresentation(comment: comment)
        let publicOpenSSH = makeOpenSSHPublicKeyString(privateKey.publicKey, comment: comment)
        return GeneratedKeyPair(
            privateKeyPEM: privatePEM,
            publicKeyOpenSSH: publicOpenSSH,
            keyType: .ed25519,
            comment: comment
        )
    }

    // MARK: - Private helpers

    /// Builds the standard OpenSSH single-line public key string:
    /// `ssh-ed25519 BASE64(wireBlob) [comment]`
    private static func makeOpenSSHPublicKeyString(_ key: Curve25519.Signing.PublicKey, comment: String) -> String {
        var blob = Data()

        func writeSSHString(_ string: String) {
            let d = string.data(using: .utf8)!
            appendUInt32BE(UInt32(d.count), to: &blob)
            blob.append(d)
        }

        func writeSSHData(_ d: Data) {
            appendUInt32BE(UInt32(d.count), to: &blob)
            blob.append(d)
        }

        writeSSHString("ssh-ed25519")
        writeSSHData(key.rawRepresentation)

        let b64 = blob.base64EncodedString()
        return comment.isEmpty ? "ssh-ed25519 \(b64)" : "ssh-ed25519 \(b64) \(comment)"
    }

    private static func appendUInt32BE(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >>  8) & 0xFF))
        data.append(UInt8( value        & 0xFF))
    }
}
