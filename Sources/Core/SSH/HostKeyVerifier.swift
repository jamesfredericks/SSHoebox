import Foundation
import NIOCore
import NIOSSH
import Crypto

// MARK: - Fingerprint

/// Computes the SHA-256 fingerprint of an SSH public key in the same format that
/// `ssh-keygen -lf` displays: "SHA256:<base64-without-padding>".
///
/// The input to the hash is the SSH wire encoding of the public key — the same
/// bytes that are base64-encoded in an authorized_keys / known_hosts file.
public func sshFingerprint(for key: NIOSSHPublicKey) -> String {
    // String(openSSHPublicKey:) produces "keyType base64WireBytes"
    let openSSHStr = String(openSSHPublicKey: key)
    let parts = openSSHStr.split(separator: " ", maxSplits: 1)
    guard parts.count >= 2,
          let wireBytes = Data(base64Encoded: String(parts[1])) else {
        return "SHA256:(unknown)"
    }
    let digest = SHA256.hash(data: wireBytes)
    // OpenSSH omits trailing '=' padding in its fingerprint display
    let b64 = Data(digest).base64EncodedString()
        .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    return "SHA256:\(b64)"
}

// MARK: - Capturing validator (TOFU)

/// An SSH host key validator that unconditionally trusts the offered key and
/// records it for later inspection.
///
/// Used on first connection to a previously-unseen host (Trust On First Use).
/// After `SSHClient.connect(to:)` returns, read `capturedKey` to get the
/// key that was presented during the handshake.
public final class CapturingHostKeyValidator: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var _capturedKey: NIOSSHPublicKey?

    public var capturedKey: NIOSSHPublicKey? {
        lock.withLock { _capturedKey }
    }

    public init() {}

    public func validateHostKey(
        hostKey: NIOSSHPublicKey,
        validationCompletePromise: EventLoopPromise<Void>
    ) {
        lock.withLock { _capturedKey = hostKey }
        validationCompletePromise.succeed(())
    }
}
