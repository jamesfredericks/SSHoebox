import Foundation
import Darwin
import NIO


/// Serves the OpenSSH agent protocol on a Unix socket.
///
/// Each instance binds the socket at most once. `stop()` only removes the socket file
/// this instance created (matched by device and inode), so an old server shutting down
/// late can't delete the socket of a newer server that has since bound the same path.
public class SSHAgentServer {
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let socketPath: String
    private let lock = NSLock()
    private var channel: Channel?
    private var boundSocket: SocketFileID?
    private var isStarted = false
    private var isStopped = false
    private weak var delegate: SSHAgentDelegate?

    /// Sockets currently served by any server in this process, so `SSHAgentClient` can
    /// refuse to use SSHoebox's own agent as an external one.
    private static let liveSocketsLock = NSLock()
    private static var liveSockets: [SocketFileID] = []

    /// Whether `path` is a socket an `SSHAgentServer` in this process is serving.
    static func isServing(path: String) -> Bool {
        // stat follows symlinks, so a link to our socket is caught too.
        var info = stat()
        guard stat(path, &info) == 0 else { return false }
        return liveSocketsLock.withLock {
            liveSockets.contains { $0.device == info.st_dev && $0.inode == info.st_ino }
        }
    }

    public init(socketPath: String, delegate: SSHAgentDelegate) {
        self.socketPath = socketPath
        self.delegate = delegate
    }

    public func start() async throws {
        try lock.withLock {
            guard !isStopped else { throw SSHAgentError.serverStopped }
            guard !isStarted else { throw SSHAgentError.serverAlreadyStarted }
            isStarted = true
        }
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

        // Bind the socket ourselves: a socket bound by NIO's `bind(unixDomainSocketPath:)`
        // unlinks its path when it closes, which would delete a newer server's socket.
        let (descriptor, socket) = try Self.bindSocket(at: socketPath)
        let channel: Channel
        do {
            channel = try await bootstrap.withBoundSocket(descriptor).get()
        } catch {
            Self.removeSocket(at: socketPath, ifItIs: socket)
            throw error
        }

        // stop() may have run while we were binding; if so, undo the bind here.
        let keep = lock.withLock { () -> Bool in
            guard !isStopped else { return false }
            self.channel = channel
            self.boundSocket = socket
            return true
        }
        if keep {
            Self.liveSocketsLock.withLock { Self.liveSockets.append(socket) }
        }
        guard keep else {
            try? await channel.close()
            Self.removeSocket(at: socketPath, ifItIs: socket)
            throw SSHAgentError.serverStopped
        }
        print("SSH Agent listening on \(socketPath)")
    }

    /// Closes the listener and removes the socket file if it is still the one this
    /// server bound. Safe to call more than once, and before `start()` has finished.
    public func stop() async throws {
        let (channel, socket, wasStopped) = lock.withLock { () -> (Channel?, SocketFileID?, Bool) in
            defer {
                isStopped = true
                self.channel = nil
                boundSocket = nil
            }
            return (self.channel, boundSocket, isStopped)
        }
        guard !wasStopped else { return }

        if let socket {
            Self.liveSocketsLock.withLock { Self.liveSockets.removeAll { $0 == socket } }
        }
        try? await channel?.close()
        Self.removeSocket(at: socketPath, ifItIs: socket)
        try await group.shutdownGracefully()
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

    /// Identifies a socket file by device and inode, which change whenever the path is
    /// unlinked and bound again.
    struct SocketFileID: Equatable {
        let device: dev_t
        let inode: ino_t

        init?(path: String) {
            var info = stat()
            guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK else { return nil }
            device = info.st_dev
            inode = info.st_ino
        }
    }

    /// Creates a Unix stream socket bound to `path` and restricts the socket file to the
    /// owner. NIO starts listening on the descriptor.
    private static func bindSocket(at path: String) throws -> (CInt, SocketFileID) {
        func posixError() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw SSHAgentError.socketPathTooLong(path)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw posixError() }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, let socket = SocketFileID(path: path) else {
            let error = posixError()
            close(descriptor)
            throw error
        }

        // The directory is already private, but don't rely on the umask for the socket
        // itself: connecting needs write access, so 0600 limits it to the owner.
        guard chmod(path, 0o600) == 0 else {
            let error = posixError()
            close(descriptor)
            removeSocket(at: path, ifItIs: socket)
            throw error
        }
        return (descriptor, socket)
    }

    static func removeSocket(at path: String, ifItIs socket: SocketFileID?) {
        guard let socket = socket, SocketFileID(path: path) == socket else { return }
        unlink(path)
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
