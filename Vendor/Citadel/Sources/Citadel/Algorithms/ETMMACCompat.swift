import Foundation
import NIO
import NIOSSH

/// A dummy NIOSSHTransportProtection that exists solely to advertise ETM
/// (Encrypt-then-MAC) MAC algorithm names during SSH key exchange negotiation.
///
/// Modern OpenSSH servers (9.x+) often offer only ETM MAC variants
/// (e.g. hmac-sha2-256-etm@openssh.com). NIOSSH's built-in AES-GCM ciphers
/// don't need MACs (they're implicit), but the key exchange negotiation still
/// requires a MAC name match. By registering this scheme, the ETM names appear
/// in the client's KEXINIT, allowing negotiation to succeed. The actual cipher
/// selected will be AES-GCM, which ignores the MAC result entirely.
///
/// This scheme's cipher name is deliberately invalid so it is never selected
/// as the actual transport cipher.
public final class ETMMACCompatScheme: NIOSSHTransportProtection {
    public static let cipherName = "_etm-mac-compat-dummy"

    public static let macNames = [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
    ]

    public static let cipherBlockSize = 16

    public static func keySizes(forMac mac: String?) throws -> ExpectedKeySizes {
        .init(ivSize: 0, encryptionKeySize: 0, macKeySize: 0)
    }

    public var macBytes: Int { 0 }

    public init(initialKeys: NIOSSHSessionKeys, mac: String?) throws {
        fatalError("ETMMACCompatScheme is a negotiation shim and must not be instantiated")
    }

    public func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        fatalError("ETMMACCompatScheme is a negotiation shim and must not be instantiated")
    }

    public func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        fatalError("ETMMACCompatScheme is a negotiation shim and must not be instantiated")
    }

    public func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        fatalError("ETMMACCompatScheme is a negotiation shim and must not be instantiated")
    }

    public func encryptPacket(_ packet: NIOSSHEncryptablePayload, to outboundBuffer: inout ByteBuffer, sequenceNumber: UInt32) throws {
        fatalError("ETMMACCompatScheme is a negotiation shim and must not be instantiated")
    }
}
