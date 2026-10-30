import Foundation

/// What a credential of type `agent` stores in its encrypted blob: which external agent to ask
/// and which of its keys to use. The private key stays in the agent (Bitwarden, 1Password, …),
/// which signs on SSHoebox's behalf and can ask the user to approve each use.
public struct SSHAgentKeyReference: Codable, Equatable, Sendable {
    /// The credential `type` for agent-backed keys.
    public static let credentialType = "agent"

    /// Path of the agent's Unix socket.
    public var socketPath: String
    /// The key's OpenSSH public key line (`ssh-ed25519 AAAA… comment`).
    public var publicKey: String

    public init(socketPath: String, publicKey: String) {
        self.socketPath = socketPath
        self.publicKey = publicKey
    }

    public init(socketPath: String, identity: SSHAgentIdentity) {
        self.init(socketPath: socketPath, publicKey: identity.openSSHPublicKey)
    }

    /// The SSH wire-format public key, or nil if `publicKey` isn't a valid line.
    public var keyBlob: Data? {
        let parts = publicKey.split(separator: " ")
        guard parts.count >= 2, let blob = Data(base64Encoded: String(parts[1])),
              Self.algorithm(of: blob) == String(parts[0]) else { return nil }
        return blob
    }

    public var algorithm: String? { keyBlob.flatMap(Self.algorithm(of:)) }

    public var fingerprint: String { keyBlob.map(sshFingerprint(forBlob:)) ?? "SHA256:(unknown)" }

    /// The key's comment (usually its name in the password manager), if any.
    public var comment: String {
        let parts = publicKey.split(separator: " ", maxSplits: 2)
        return parts.count == 3 ? String(parts[2]) : ""
    }

    // MARK: - Storage

    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decode(_ data: Data) throws -> SSHAgentKeyReference {
        try JSONDecoder().decode(SSHAgentKeyReference.self, from: data)
    }

    // MARK: - Known agents

    /// An SSH agent built into a password manager, at its default socket path.
    public struct KnownAgent: Identifiable, Hashable, Sendable {
        public let name: String
        public let socketPath: String
        public var id: String { socketPath }

        public var isRunning: Bool {
            var info = stat()
            return stat(socketPath, &info) == 0 && info.st_mode & S_IFMT == S_IFSOCK
        }
    }

    /// Default socket paths of password-manager agents, Bitwarden first.
    public static var knownAgents: [KnownAgent] {
        let home = NSHomeDirectory()
        return [
            KnownAgent(name: "Bitwarden", socketPath: home + "/.bitwarden-ssh-agent.sock"),
            KnownAgent(name: "Bitwarden (App Store)",
                       socketPath: home + "/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock"),
            KnownAgent(name: "1Password",
                       socketPath: home + "/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"),
        ]
    }

    // MARK: - Helpers

    /// Reads the algorithm name at the start of a wire-format key or signature blob.
    static func algorithm(of blob: Data) -> String? {
        guard let (name, _) = readString(blob, at: blob.startIndex) else { return nil }
        return String(data: name, encoding: .utf8)
    }

    /// Reads an SSH `string` (uint32 length + bytes) starting at `offset`. Returns the bytes
    /// and the offset just past them.
    static func readString(_ data: Data, at offset: Data.Index) -> (Data, Data.Index)? {
        guard offset >= data.startIndex, data.endIndex - offset >= 4 else { return nil }
        let length = data[offset..<offset + 4].reduce(0) { $0 << 8 | Int($1) }
        let start = offset + 4
        guard data.endIndex - start >= length else { return nil }
        return (Data(data[start..<start + length]), start + length)
    }
}
