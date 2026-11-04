import Foundation
import NIOCore
import NIOSSH
import Crypto
import Citadel

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
    return sshFingerprint(forBlob: wireBytes)
}

/// The `ssh-keygen -lf` style fingerprint of an SSH wire-format public key blob.
public func sshFingerprint(forBlob wireBytes: Data) -> String {
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

// MARK: - Validator selection (fail closed)

public enum HostKeyTrustError: LocalizedError {
    case noRepository
    case lookupFailed(Error)
    case unreadableStoredKey(keyType: String)

    public var errorDescription: String? {
        switch self {
        case .noRepository:
            return "Host key verification is unavailable (no known-hosts store). Refusing to connect."
        case .lookupFailed(let error):
            return "Could not read the trusted host key record: \(error.localizedDescription). Refusing to connect."
        case .unreadableStoredKey(let keyType):
            return "The trusted \(keyType) host key on record could not be read. Refusing to connect; remove the host from Preferences → Known Hosts to trust it again."
        }
    }
}

public enum HostKeyTrust {
    /// NIOSSH only parses host key types it has registered, and Citadel registers ssh-rsa
    /// lazily inside `SSHClient.connect`. Register it up front so a stored RSA key parses
    /// on the first connection after launch instead of looking like "no key on record".
    private static let registerAlgorithms: Void = {
        NIOSSHAlgorithms.register(publicKey: Insecure.RSA.PublicKey.self, signature: Insecure.RSA.Signature.self)
    }()

    /// Chooses the host key validator for a connection.
    ///
    /// - A stored key for `host:port` is enforced with `.trustedKeys`; a different key fails
    ///   the handshake with `InvalidHostKey`.
    /// - Only when the store positively reports no record does this fall back to Trust On
    ///   First Use via `CapturingHostKeyValidator`; the caller persists the captured key.
    /// - Anything else (no store, lookup error, unparseable stored key) throws, so the
    ///   connection is refused rather than silently accepting any server key.
    ///
    /// With a `trace`, the trust state and the key the server presents are written to it.
    public static func validator(
        for host: String,
        port: Int,
        repository: KnownHostRepository?,
        trace: LoginTrace? = nil
    ) throws -> (SSHHostKeyValidator, CapturingHostKeyValidator?) {
        _ = registerAlgorithms
        guard let repository else {
            trace?.error("host key: no known-hosts store; refusing to connect")
            throw HostKeyTrustError.noRepository
        }

        let record: KnownHost?
        do {
            record = try repository.find(hostname: host, port: port)
        } catch {
            trace?.error("host key: lookup failed (\(LoginTrace.describe(error))); refusing to connect")
            throw HostKeyTrustError.lookupFailed(error)
        }

        let validator: SSHHostKeyValidator
        let capturer: CapturingHostKeyValidator?
        if let record {
            guard let storedKey = try? NIOSSHPublicKey(openSSHPublicKey: record.openSSHPublicKey) else {
                trace?.error("host key: stored \(record.keyType) key can't be parsed; refusing to connect")
                throw HostKeyTrustError.unreadableStoredKey(keyType: record.keyType)
            }
            trace?.info("host key: trusted key on record is \(record.keyType) \(record.keyFingerprint)")
            (validator, capturer) = (.trustedKeys([storedKey]), nil)
        } else {
            trace?.info("host key: none on record; the server's key will be trusted on first use")
            let newCapturer = CapturingHostKeyValidator()
            (validator, capturer) = (.custom(newCapturer), newCapturer)
        }
        guard let trace else { return (validator, capturer) }
        return (.custom(TracingHostKeyValidator(inner: validator, trace: trace)), capturer)
    }
}

/// Logs the key the server presents and whether it was accepted, then defers to `inner`.
/// Citadel's `InvalidHostKey` carries no key, so this is the only place the presented
/// fingerprint of a mismatched key can be seen.
final class TracingHostKeyValidator: NIOSSHClientServerAuthenticationDelegate, Sendable {
    private let inner: SSHHostKeyValidator
    private let trace: LoginTrace

    init(inner: SSHHostKeyValidator, trace: LoginTrace) {
        self.inner = inner
        self.trace = trace
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        let keyType = String(String(openSSHPublicKey: hostKey).split(separator: " ").first ?? "unknown")
        let presented = "\(keyType) \(sshFingerprint(for: hostKey))"
        let trace = self.trace
        trace.info("host key: server presented \(presented)")
        validationCompletePromise.futureResult.whenComplete { result in
            switch result {
            case .success:
                trace.info("host key: accepted")
            case .failure:
                trace.error("host key: REJECTED, \(presented) does not match the trusted key on record")
            }
        }
        inner.validateHostKey(hostKey: hostKey, validationCompletePromise: validationCompletePromise)
    }
}
