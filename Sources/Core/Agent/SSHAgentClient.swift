import Foundation
import Darwin
import NIOCore

/// One key offered by an external agent.
public struct SSHAgentIdentity: Identifiable, Hashable, Sendable {
    /// SSH wire-format public key (`string(algorithm) + key data`).
    public let keyBlob: Data
    public let comment: String

    public var id: Data { keyBlob }

    /// The key's algorithm name, e.g. `ssh-ed25519`, read from the blob.
    public var algorithm: String { SSHAgentKeyReference.algorithm(of: keyBlob) ?? "unknown" }

    public var fingerprint: String { sshFingerprint(forBlob: keyBlob) }

    /// The key as an `authorized_keys` / `.pub` line.
    public var openSSHPublicKey: String {
        let line = "\(algorithm) \(keyBlob.base64EncodedString())"
        return comment.isEmpty ? line : "\(line) \(comment)"
    }

    public init(keyBlob: Data, comment: String) {
        self.keyBlob = keyBlob
        self.comment = comment
    }
}

/// A client for an external SSH agent (Bitwarden, 1Password, `ssh-agent`) on a Unix socket.
///
/// Calls block until the agent replies, which for a sign request can mean waiting for the
/// user to approve it in their password manager, so never call them on the main thread.
/// Each request uses its own connection, as `ssh` does.
public final class SSHAgentClient: Sendable {
    /// How long to wait for a reply. Long enough to read and approve a prompt.
    public static let defaultTimeout: TimeInterval = 90

    public let socketPath: String
    private let timeout: TimeInterval

    public init(socketPath: String, timeout: TimeInterval = SSHAgentClient.defaultTimeout) {
        self.socketPath = socketPath
        self.timeout = timeout
    }

    /// The keys the agent offers.
    public func identities() throws -> [SSHAgentIdentity] {
        switch try request(.requestIdentities) {
        case .identitiesAnswer(let identities):
            return identities.map { SSHAgentIdentity(keyBlob: $0.key, comment: $0.comment) }
        case .failure:
            return []
        default:
            throw SSHAgentClientError.protocolError
        }
    }

    /// Asks the agent to sign `data` with the key `keyBlob`. Returns the signature blob
    /// (`string(algorithm) + string(signature)`).
    public func sign(keyBlob: Data, data: Data, flags: UInt32 = 0) throws -> Data {
        switch try request(.signRequest(key: keyBlob, data: data, flags: flags)) {
        case .signResponse(let signature):
            return signature
        case .failure:
            throw SSHAgentClientError.signingRefused
        default:
            throw SSHAgentClientError.protocolError
        }
    }

    // MARK: - Transport

    private func request(_ message: SSHAgentMessage) throws -> SSHAgentMessage {
        let descriptor = try connect()
        defer { close(descriptor) }

        var body = ByteBufferAllocator().buffer(capacity: 256)
        SSHAgentProtocol.serialize(request: message, into: &body)
        var frame = ByteBufferAllocator().buffer(capacity: 4 + body.readableBytes)
        frame.writeInteger(UInt32(body.readableBytes))
        frame.writeBuffer(&body)
        try writeAll(descriptor, Array(frame.readableBytesView))

        var header = ByteBuffer(bytes: try readExactly(descriptor, count: 4))
        let length = header.readInteger(as: UInt32.self) ?? 0
        guard length > 0, length <= SSHAgentProtocol.maxMessageLength else {
            throw SSHAgentClientError.protocolError
        }
        var reply = ByteBuffer(bytes: try readExactly(descriptor, count: Int(length)))
        do {
            return try SSHAgentProtocol.parseResponse(buffer: &reply)
        } catch {
            throw SSHAgentClientError.protocolError
        }
    }

    /// Connects to the socket after checking it's a socket owned by the current user (and not
    /// SSHoebox's own agent), then checks the process at the other end runs as the same user.
    private func connect() throws -> Int32 {
        guard !SSHAgentServer.isServing(path: socketPath) else { throw SSHAgentClientError.ownAgent }

        var info = stat()
        guard stat(socketPath, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK else {
            throw SSHAgentClientError.agentNotRunning(socketPath)
        }
        guard info.st_uid == getuid() else { throw SSHAgentClientError.untrustedAgent(socketPath) }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw SSHAgentError.socketPathTooLong(socketPath)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }

        var noSigPipe: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var time = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &time, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &time, socklen_t(MemoryLayout<timeval>.size))

        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            close(descriptor)
            throw SSHAgentClientError.agentNotRunning(socketPath)
        }

        var credentials = xucred()
        var size = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &size) == 0,
              credentials.cr_version == XUCRED_VERSION,
              credentials.cr_uid == getuid() else {
            close(descriptor)
            throw SSHAgentClientError.untrustedAgent(socketPath)
        }
        return descriptor
    }

    private func writeAll(_ descriptor: Int32, _ bytes: [UInt8]) throws {
        var offset = 0
        while offset < bytes.count {
            let written = bytes[offset...].withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, 0) }
            if written < 0 {
                if errno == EINTR { continue }
                throw errno == EAGAIN ? SSHAgentClientError.timedOut : SSHAgentClientError.protocolError
            }
            offset += written
        }
    }

    private func readExactly(_ descriptor: Int32, count: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let read = bytes[offset...].withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
            if read < 0 {
                if errno == EINTR { continue }
                // SO_RCVTIMEO expiring shows up as EAGAIN.
                throw errno == EAGAIN ? SSHAgentClientError.timedOut : SSHAgentClientError.protocolError
            }
            // The agent hung up mid-reply.
            guard read > 0 else { throw SSHAgentClientError.protocolError }
            offset += read
        }
        return bytes
    }
}
