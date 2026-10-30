import Foundation
import NIOCore
import NIOSSH

/// Public-key login with a key held by an external SSH agent. NIOSSH signs through the
/// `NIOSSHPrivateKeyProtocol` hook, which here forwards the request to the agent, so the
/// private key never enters this process.
///
/// The hook is synchronous and the agent may wait for the user to approve the request, so the
/// signing call blocks its event loop. Connections using these keys therefore get an event
/// loop of their own (see `SSHSessionManager.connect(host:port:username:agentKey:terminalSize:)`).
public enum AgentBackedKey {
    /// Key types that can be used through an agent. RSA isn't among them: NIOSSH names the
    /// login algorithm after the key type (`ssh-rsa`, i.e. SHA-1), which servers now refuse.
    public static let supportedAlgorithms: Set<String> = [
        AgentEd25519.name, AgentECDSAP256.name, AgentECDSAP384.name, AgentECDSAP521.name,
    ]

    /// How long login may take: the agent's own timeout for an approval, plus the handshake.
    public static let loginTimeout: TimeAmount = .seconds(Int64(SSHAgentClient.defaultTimeout) + 30)

    /// Checks the agent is reachable and still offers the key, then builds it. Doing this before
    /// connecting turns "Bitwarden isn't running" or "key deleted" into a clear message rather
    /// than a failed login.
    @MainActor
    public static func checkedPrivateKey(for reference: SSHAgentKeyReference) async throws -> NIOSSHPrivateKey {
        guard let blob = reference.keyBlob, let algorithm = reference.algorithm else {
            throw SSHAgentClientError.protocolError
        }
        guard supportedAlgorithms.contains(algorithm) else {
            throw SSHAgentClientError.unsupportedKeyType(algorithm)
        }
        let socketPath = reference.socketPath
        try await Task.detached {
            let identities = try SSHAgentClient(socketPath: socketPath).identities()
            guard identities.contains(where: { $0.keyBlob == blob }) else {
                throw SSHAgentClientError.keyNotFound(reference.fingerprint)
            }
        }.value
        return try privateKey(for: reference)
    }

    /// Builds a NIOSSH private key whose signatures come from the agent at `reference.socketPath`.
    public static func privateKey(for reference: SSHAgentKeyReference) throws -> NIOSSHPrivateKey {
        guard let blob = reference.keyBlob, let algorithm = reference.algorithm else {
            throw SSHAgentClientError.protocolError
        }
        let client = SSHAgentClient(socketPath: reference.socketPath)
        switch algorithm {
        case AgentEd25519.name:
            return NIOSSHPrivateKey(custom: AgentPrivateKey<AgentEd25519>(client: client, keyBlob: blob))
        case AgentECDSAP256.name:
            return NIOSSHPrivateKey(custom: AgentPrivateKey<AgentECDSAP256>(client: client, keyBlob: blob))
        case AgentECDSAP384.name:
            return NIOSSHPrivateKey(custom: AgentPrivateKey<AgentECDSAP384>(client: client, keyBlob: blob))
        case AgentECDSAP521.name:
            return NIOSSHPrivateKey(custom: AgentPrivateKey<AgentECDSAP521>(client: client, keyBlob: blob))
        default:
            throw SSHAgentClientError.unsupportedKeyType(algorithm)
        }
    }
}

// MARK: - Key types

protocol AgentKeyAlgorithm {
    static var name: String { get }
}

enum AgentEd25519: AgentKeyAlgorithm { static let name = "ssh-ed25519" }
enum AgentECDSAP256: AgentKeyAlgorithm { static let name = "ecdsa-sha2-nistp256" }
enum AgentECDSAP384: AgentKeyAlgorithm { static let name = "ecdsa-sha2-nistp384" }
enum AgentECDSAP521: AgentKeyAlgorithm { static let name = "ecdsa-sha2-nistp521" }

/// A private key that lives in an agent. Its signature is the agent's reply.
struct AgentPrivateKey<Algorithm: AgentKeyAlgorithm>: NIOSSHPrivateKeyProtocol {
    static var keyPrefix: String { Algorithm.name }

    let client: SSHAgentClient
    let keyBlob: Data

    var publicKey: NIOSSHPublicKeyProtocol {
        // The blob is `string(algorithm) + key data`; NIOSSH writes the algorithm itself.
        let afterName = SSHAgentKeyReference.readString(keyBlob, at: keyBlob.startIndex)?.1 ?? keyBlob.endIndex
        return AgentPublicKey<Algorithm>(rawRepresentation: Data(keyBlob[afterName...]))
    }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        let blob = try client.sign(keyBlob: keyBlob, data: Data(data))
        // The reply is `string(algorithm) + string(signature)`, the same layout SSH sends.
        guard let (name, afterName) = SSHAgentKeyReference.readString(blob, at: blob.startIndex),
              String(data: name, encoding: .utf8) == Algorithm.name,
              let (signature, _) = SSHAgentKeyReference.readString(blob, at: afterName) else {
            throw SSHAgentClientError.protocolError
        }
        return AgentSignature<Algorithm>(rawRepresentation: signature)
    }
}

/// The public half of an `AgentPrivateKey`, holding the key data that follows the algorithm
/// name in its wire format (for ECDSA that includes the curve name).
struct AgentPublicKey<Algorithm: AgentKeyAlgorithm>: NIOSSHPublicKeyProtocol {
    static var publicKeyPrefix: String { Algorithm.name }

    let rawRepresentation: Data

    /// Only servers verify signatures, and a client never acts as one for its own key.
    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        false
    }

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeBytes(rawRepresentation)
    }

    /// Not used: these keys are only ever sent, never parsed from the wire.
    static func read(from buffer: inout ByteBuffer) throws -> AgentPublicKey<Algorithm> {
        throw SSHAgentClientError.protocolError
    }
}

/// A signature made by the agent: the bytes inside the reply's signature `string`.
struct AgentSignature<Algorithm: AgentKeyAlgorithm>: NIOSSHSignatureProtocol {
    static var signaturePrefix: String { Algorithm.name }

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeInteger(UInt32(rawRepresentation.count)) + buffer.writeBytes(rawRepresentation)
    }

    /// Not used: these signatures are only ever sent, never parsed from the wire.
    static func read(from buffer: inout ByteBuffer) throws -> AgentSignature<Algorithm> {
        throw SSHAgentClientError.protocolError
    }
}

// MARK: - Authenticator

/// Logs in with one agent-held key. Like `KeyboardInteractiveAuthenticator`, it first sends a
/// `none` request to learn what the server accepts, so a server that doesn't take public keys
/// never causes an approval prompt in the password manager.
///
/// NIOSSH calls it on the connection's event loop, one call at a time.
final class AgentKeyAuthenticator: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private let username: String
    private let privateKey: NIOSSHPrivateKey
    private var probed = false
    private var offered = false

    init(username: String, privateKey: NIOSSHPrivateKey) {
        self.username = username
        self.privateKey = privateKey
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        func offer(_ offer: NIOSSHUserAuthenticationOffer.Offer) {
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(
                username: username, serviceName: "ssh-connection", offer: offer))
        }

        guard probed else {
            probed = true
            offer(.none)
            return
        }

        if !offered, availableMethods.contains(.publicKey) {
            offered = true
            offer(.privateKey(.init(privateKey: privateKey)))
        } else if offered {
            nextChallengePromise.fail(SSHLoginError.rejected)
        } else {
            nextChallengePromise.fail(SSHLoginError.noUsableMethod("public key"))
        }
    }
}
