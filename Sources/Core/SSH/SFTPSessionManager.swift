import Foundation
import Citadel
import Crypto
import NIOSSH
import NIOCore
import NIOPosix

// MARK: - SFTPEntry

public struct SFTPEntry: Identifiable, Hashable, Sendable {
    public var id: String { path }
    public let filename: String
    public let path: String
    public let isDirectory: Bool
    public let isSymlink: Bool
    public let size: UInt64?
    public let modifiedDate: Date?
    public let permissions: UInt32?

    public var isHidden: Bool { filename.hasPrefix(".") }

    public var formattedSize: String {
        guard !isDirectory, let bytes = size else { return "—" }
        switch bytes {
        case 0..<1_024: return "\(bytes) B"
        case 1_024..<1_048_576: return String(format: "%.1f KB", Double(bytes) / 1_024)
        case 1_048_576..<1_073_741_824: return String(format: "%.1f MB", Double(bytes) / 1_048_576)
        default: return String(format: "%.2f GB", Double(bytes) / 1_073_741_824)
        }
    }

    public var systemImage: String {
        if isDirectory { return "folder.fill" }
        if isSymlink   { return "link" }
        let ext = (filename as NSString).pathExtension.lowercased()
        switch ext {
        case "png", "jpg", "jpeg", "gif", "svg", "webp", "heic": return "photo.fill"
        case "mp4", "mov", "avi", "mkv", "m4v":                  return "film.fill"
        case "mp3", "wav", "aac", "flac", "m4a":                 return "music.note"
        case "zip", "tar", "gz", "bz2", "xz", "7z", "rar":       return "archivebox.fill"
        case "sh", "bash", "zsh", "fish":                        return "terminal.fill"
        case "py", "rb", "js", "ts", "go", "rs", "swift", "c",
             "cpp", "h":                                          return "curlybraces"
        case "pdf":                                               return "doc.richtext.fill"
        case "txt", "md", "log", "conf", "yaml", "yml", "toml",
             "json", "xml", "ini":                               return "doc.text.fill"
        default:                                                  return "doc.fill"
        }
    }
}

// MARK: - SFTPSessionManager

/// Manages an SSH+SFTP connection and provides high-level file-browser operations.
@MainActor
public class SFTPSessionManager: ObservableObject {

    public enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case connected
        case failed(String)
    }

    @Published public var connectionState: ConnectionState = .disconnected
    @Published public var currentPath: String = "/"
    @Published public var entries: [SFTPEntry] = []
    @Published public var isLoading: Bool = false
    @Published public var errorMessage: String?

    private var sftpClient: SFTPClient?
    /// Bumped by `disconnect()` so a connect still in flight knows to close what it opened.
    private var generation = 0

    /// Set before calling connect to enable TOFU host key validation.
    public var knownHostRepository: KnownHostRepository?

    /// The id of the latest login attempt, for finding it in the Login Log.
    @Published public private(set) var lastLoginAttemptID: String?

    private func newTrace() -> LoginTrace {
        let trace = LoginTrace()
        lastLoginAttemptID = trace.id
        return trace
    }

    /// Set when a PEM key requires a passphrase. The UI observes this to show a prompt.
    @Published public var passphraseChallenge: SSHPassphraseChallenge? = nil

    /// The current connection (target plus any jump hosts).
    private var route: SSHRoute?
    private var keepAliveTask: Task<Void, Never>?

    public init() {}

    // MARK: - Connect

    /// Logs in to `target`, through `jumps` if any, and opens the SFTP subsystem. Nothing can
    /// answer login prompts here, so a stored password only answers the password prompt.
    public func connect(_ target: SSHLogin, via jumps: [SSHLogin] = [],
                        options: SSHSessionOptions = SSHSessionOptions()) async {
        let gen = generation
        passphraseChallenge = nil
        connectionState = .connecting
        isLoading = true
        errorMessage = nil

        let trace = newTrace()
        trace.begin("SFTP", host: target.host, port: target.port, username: target.username,
                    method: target.auth.methodDescriptionForTrace)
        if !jumps.isEmpty {
            trace.info("route: through \(jumps.map(\.endpoint).joined(separator: ", then ")) (ssh -J)")
        }

        func fail(_ state: String, _ message: String) {
            connectionState = .failed(state)
            errorMessage = message
            isLoading = false
        }

        let preparer = SSHLoginPreparer(repository: knownHostRepository, trace: trace, prompter: nil)
        var prepared: [PreparedLogin] = []
        for (index, login) in (jumps + [target]).enumerated() {
            let isTarget = index == jumps.count
            let outcome = await preparer.prepare(login)
            guard generation == gen else {
                trace.info("cancelled while preparing the login")
                return
            }
            switch outcome {
            case .ready(let step):
                prepared.append(step)
            case .needsPassphrase:
                connectionState = .disconnected
                isLoading = false
                passphraseChallenge = SSHPassphraseChallenge(target: target, jumps: jumps,
                                                             jumpIndex: isTarget ? nil : index,
                                                             options: options, terminalSize: (80, 24))
                return
            case .failed(let message):
                let prefix = isTarget ? "" : "Jump host \(login.endpoint): "
                fail(prefix + message, prefix + message)
                return
            }
        }

        var openedRoute: SSHRoute?
        do {
            let route = try await SSHRoute.connect(prepared, repository: knownHostRepository, trace: trace)
            openedRoute = route
            trace.info("auth: SUCCESS, logged in")

            trace.info("sftp: opening the sftp subsystem")
            let sftp = try await route.client.openSFTP()
            let home = (try? await sftp.getRealPath(atPath: ".")) ?? "/"

            // The browser was closed while connecting: don't keep a connection nobody owns.
            guard generation == gen else {
                trace.info("logged in, but the browser was closed meanwhile; closing")
                try? await sftp.close()
                await route.close()
                return
            }
            self.route = route
            self.sftpClient = sftp
            self.connectionState = .connected
            trace.info("sftp: ready, home directory \(LoginTrace.quoted(home)); login complete")
            if options.keepAliveInterval > 0 {
                keepAliveTask = SSHKeepAlive.start(route: route, interval: options.keepAliveInterval,
                                                   countMax: options.keepAliveCountMax,
                                                   endpoint: target.endpoint) { [weak self] in
                    await route.close()
                    await self?.connectionLost(generation: gen)
                }
            }
            await loadDirectory(at: home)

        } catch is InvalidHostKey {
            await openedRoute?.close()
            guard generation == gen else { return }
            trace.error("failed: host key mismatch (see the presented and trusted fingerprints above)")
            fail("Host key mismatch", "Host key mismatch — remove the entry from Preferences → Known Hosts and reconnect.")
        } catch {
            await openedRoute?.close()
            guard generation == gen else {
                trace.info("ended by a disconnect (\(LoginTrace.describe(error)))")
                return
            }
            trace.error("failed: \(LoginTrace.describe(error))")
            let message = (error as? SSHAgentClientError)?.localizedDescription ?? error.localizedDescription
            fail(message, message)
        }
    }

    private func connectionLost(generation gen: Int) {
        guard generation == gen else { return }
        connectionState = .failed("Connection lost")
        errorMessage = "The server stopped answering keep-alives; the connection was closed."
    }

    /// Connects again with the passphrase the user gave for the challenge's key.
    public func connect(answering challenge: SSHPassphraseChallenge, passphrase: String) async {
        let (target, jumps) = challenge.answered(with: passphrase)
        await connect(target, via: jumps, options: challenge.options)
    }

    public func connect(host: String, port: Int, username: String, password: String) async {
        await connect(SSHLogin(host: host, port: port, username: username, auth: .password(password)))
    }

    public func connect(host: String, port: Int, username: String, pemKey: String, passphrase: String? = nil) async {
        await connect(SSHLogin(host: host, port: port, username: username,
                               auth: .privateKey(pem: pemKey, passphrase: passphrase)))
    }

    /// Logs in with a key held by an external agent, which may ask the user to approve it.
    public func connect(host: String, port: Int, username: String, agentKey: SSHAgentKeyReference) async {
        await connect(SSHLogin(host: host, port: port, username: username, auth: .agentKey(agentKey)))
    }

    // MARK: - Navigation

    public func navigate(to path: String) async {
        guard connectionState == .connected else { return }
        await loadDirectory(at: path)
    }

    public func navigateUp() async {
        guard currentPath != "/" else { return }
        let parent = (currentPath as NSString).deletingLastPathComponent
        await loadDirectory(at: parent.isEmpty ? "/" : parent)
    }

    public func refresh() async {
        await loadDirectory(at: currentPath)
    }

    private func loadDirectory(at path: String) async {
        guard let sftp = sftpClient else { return }
        isLoading = true
        errorMessage = nil
        do {
            let batches = try await sftp.listDirectory(atPath: path)
            let all = batches.flatMap { $0.components }
            let filtered: [SFTPEntry] = all.compactMap { c in
                guard c.filename != ".", c.filename != ".." else { return nil }
                let perms  = c.attributes.permissions ?? 0
                let isDir  = (perms & 0o170000) == 0o040000
                let isLink = (perms & 0o170000) == 0o120000
                let full   = path == "/" ? "/\(c.filename)" : "\(path)/\(c.filename)"
                return SFTPEntry(
                    filename:    c.filename,
                    path:        full,
                    isDirectory: isDir,
                    isSymlink:   isLink,
                    size:        c.attributes.size,
                    modifiedDate: c.attributes.accessModificationTime?.modificationTime,
                    permissions: perms
                )
            }
            .sorted {
                if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
                return $0.filename.localizedCaseInsensitiveCompare($1.filename) == .orderedAscending
            }
            currentPath = path
            entries = filtered
        } catch {
            errorMessage = "Cannot read '\(path)': \(error.localizedDescription)"
        }
        isLoading = false
    }

    // MARK: - File operations

    public func downloadData(for entry: SFTPEntry) async throws -> Data {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let buffer = try await sftp.withFile(filePath: entry.path, flags: .read) { file in
            try await file.readAll()
        }
        guard let data = buffer.getData(at: 0, length: buffer.readableBytes) else {
            throw SFTPManagerError.readFailed
        }
        return data
    }

    public func upload(data: Data, named filename: String) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let dest = currentPath == "/" ? "/\(filename)" : "\(currentPath)/\(filename)"
        let buf  = ByteBuffer(data: data)
        try await sftp.withFile(filePath: dest, flags: [.write, .create, .truncate]) { file in
            try await file.write(buf)
        }
        await refresh()
    }

    public func createDirectory(named name: String) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let dest = currentPath == "/" ? "/\(name)" : "\(currentPath)/\(name)"
        try await sftp.createDirectory(atPath: dest)
        await refresh()
    }

    public func delete(entry: SFTPEntry) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        if entry.isDirectory {
            try await sftp.rmdir(at: entry.path)
        } else {
            try await sftp.remove(at: entry.path)
        }
        await refresh()
    }

    public func rename(entry: SFTPEntry, to newName: String) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let parent  = (entry.path as NSString).deletingLastPathComponent
        let newPath = parent == "/" ? "/\(newName)" : "\(parent)/\(newName)"
        try await sftp.rename(at: entry.path, to: newPath)
        await refresh()
    }

    // MARK: - Disconnect

    public func disconnect() {
        let sftp = sftpClient
        let route = self.route
        sftpClient = nil
        self.route = nil
        keepAliveTask?.cancel()
        keepAliveTask = nil
        passphraseChallenge = nil
        generation += 1
        connectionState = .disconnected
        isLoading  = false
        entries    = []
        currentPath = "/"
        Task {
            try? await sftp?.close()
            await route?.close()
        }
    }
}

// MARK: - Errors

public enum SFTPManagerError: LocalizedError {
    case notConnected
    case readFailed

    public var errorDescription: String? {
        switch self {
        case .notConnected: return "Not connected to SFTP server"
        case .readFailed:   return "Failed to read file data"
        }
    }
}
