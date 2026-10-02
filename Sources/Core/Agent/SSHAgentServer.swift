import Foundation
import Darwin
import NIO


public class SSHAgentServer {
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private var channel: Channel?
    private let socketPath: String
    private weak var delegate: SSHAgentDelegate?

    public init(socketPath: String, delegate: SSHAgentDelegate) {
        self.socketPath = socketPath
        self.delegate = delegate
    }

    public func start() async throws {
        try Self.prepareSocketDirectory(for: socketPath)
        try Self.removeStaleSocket(at: socketPath)

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [weak delegate = self.delegate] channel in
                // Only the user running the app may talk to the agent. A failed future
                // makes NIO close the connection before any handler sees its bytes.
                Self.peerUID(of: channel).flatMap { uid in
                    guard uid == getuid() else {
                        print("SSH Agent: rejected connection from uid \(uid)")
                        return channel.eventLoop.makeFailedFuture(SSHAgentError.unauthorizedPeer(uid: uid))
                    }
                    guard let delegate = delegate else {
                        return channel.close()
                    }
                    return channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandlers(
                            ByteToMessageHandler(SSHAgentFrameDecoder()),
                            SSHAgentHandler(delegate: delegate))
                    }
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_keepalive), value: 1)

        let channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
        self.channel = channel

        // The directory is already private, but don't rely on the umask for the socket
        // itself: connecting needs write access, so 0600 limits it to the owner.
        guard chmod(socketPath, 0o600) == 0 else {
            let code = errno
            try? await channel.close()
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EPERM)
        }
        print("SSH Agent listening on \(socketPath)")
    }

    public func stop() async throws {
        try await channel?.close()
        try await group.shutdownGracefully()

        // Clean up socket file
        if FileManager.default.fileExists(atPath: socketPath) {
            try? FileManager.default.removeItem(atPath: socketPath)
        }
    }

    // MARK: - Socket security

    /// Ensures the socket's directory exists, belongs to the current user and is 0700, so
    /// no other user can reach (or replace) the socket inside it.
    static func prepareSocketDirectory(for socketPath: String) throws {
        let directory = (socketPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])

        // stat (not lstat): a symlinked directory is fine as long as its target is ours.
        var info = stat()
        guard stat(directory, &info) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENOENT)
        }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid() else {
            throw SSHAgentError.insecureSocketDirectory(directory)
        }
        if info.st_mode & 0o077 != 0, chmod(directory, 0o700) != 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EPERM)
        }
    }

    /// Removes a socket left behind by an earlier run. Refuses to delete anything that
    /// isn't a socket, in case the path was pointed at a real file.
    static func removeStaleSocket(at socketPath: String) throws {
        var info = stat()
        guard lstat(socketPath, &info) == 0 else { return }
        guard info.st_mode & S_IFMT == S_IFSOCK else {
            throw SSHAgentError.socketPathInUse(socketPath)
        }
        guard unlink(socketPath) == 0 || errno == ENOENT else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EPERM)
        }
    }

    /// Reads the connecting process's effective uid via `LOCAL_PEERCRED`.
    private static func peerUID(of channel: Channel) -> EventLoopFuture<uid_t> {
        guard let provider = channel as? SocketOptionProvider else {
            return channel.eventLoop.makeFailedFuture(SSHAgentError.unauthorizedPeer(uid: nil))
        }
        return provider.unsafeGetSocketOption(level: NIOBSDSocket.OptionLevel(rawValue: SOL_LOCAL),
                                              name: NIOBSDSocket.Option(rawValue: LOCAL_PEERCRED))
            .flatMapThrowing { (credentials: xucred) in
                guard credentials.cr_version == XUCRED_VERSION else {
                    throw SSHAgentError.unauthorizedPeer(uid: nil)
                }
                return credentials.cr_uid
            }
    }
}
