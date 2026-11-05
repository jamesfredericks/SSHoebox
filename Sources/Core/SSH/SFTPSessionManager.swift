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

    var sftpClient: SFTPClient?
    /// Bumped by `disconnect()` so a connect still in flight knows to close what it opened.
    var generation = 0

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

    /// Uploads and downloads, newest last, including finished ones until cleared.
    @Published public internal(set) var transfers: [SFTPTransfer] = []
    var transferWorker: Task<Void, Never>?
    var cancelledTransfers: Set<UUID> = []

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

    /// The entries of a remote folder (without `.` and `..`), folders first, by name.
    func listEntries(at path: String) async throws -> [SFTPEntry] {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let batches = try await sftp.listDirectory(atPath: path)
        return batches.flatMap { $0.components }.compactMap { c in
            guard c.filename != ".", c.filename != ".." else { return nil }
            let perms  = c.attributes.permissions ?? 0
            let isDir  = (perms & 0o170000) == 0o040000
            let isLink = (perms & 0o170000) == 0o120000
            return SFTPEntry(
                filename:    c.filename,
                path:        Self.join(path, c.filename),
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
    }

    static func join(_ folder: String, _ name: String) -> String {
        folder == "/" ? "/\(name)" : (folder.hasSuffix("/") ? folder + name : "\(folder)/\(name)")
    }

    private func loadDirectory(at path: String) async {
        guard sftpClient != nil else { return }
        isLoading = true
        errorMessage = nil
        do {
            let filtered = try await listEntries(at: path)
            currentPath = path
            entries = filtered
        } catch {
            errorMessage = "Cannot read '\(path)': \(error.localizedDescription)"
        }
        isLoading = false
    }

    // MARK: - File operations

    public func createDirectory(named name: String) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let dest = currentPath == "/" ? "/\(name)" : "\(currentPath)/\(name)"
        try await sftp.createDirectory(atPath: dest)
        await refresh()
    }

    /// Deletes a file, or a folder with everything in it.
    public func delete(entry: SFTPEntry) async throws {
        try await deleteRecursively(entry)
        await refresh()
    }

    /// Deletes several entries; stops at the first failure.
    public func delete(entries: [SFTPEntry]) async throws {
        defer { Task { await refresh() } }
        for entry in entries { try await deleteRecursively(entry) }
    }

    private func deleteRecursively(_ entry: SFTPEntry) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        if entry.isDirectory && !entry.isSymlink {
            for child in try await listEntries(at: entry.path) {
                try await deleteRecursively(child)
            }
            try await sftp.rmdir(at: entry.path)
        } else {
            try await sftp.remove(at: entry.path)
        }
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
        transferWorker?.cancel()
        transferWorker = nil
        for index in transfers.indices where transfers[index].isActive {
            transfers[index].state = .cancelled
        }
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

// MARK: - Transfers

/// A file or folder being copied to or from the server.
public struct SFTPTransfer: Identifiable, Equatable {
    public enum Direction: Equatable, Sendable { case upload, download }
    public enum State: Equatable {
        case queued
        case running
        case finished
        case failed(String)
        case cancelled
    }

    public let id = UUID()
    public let direction: Direction
    public let name: String
    public let localURL: URL
    public let remotePath: String
    /// Known once the files are counted (a folder is walked first).
    public var totalBytes: UInt64?
    public var transferredBytes: UInt64 = 0
    public var fileCount = 0
    public var filesDone = 0
    public var state: State = .queued

    public var isActive: Bool { state == .queued || state == .running }

    public var fractionCompleted: Double? {
        guard let totalBytes else { return nil }
        return totalBytes == 0 ? (state == .finished ? 1 : 0) : min(1, Double(transferredBytes) / Double(totalBytes))
    }
}

extension SFTPSessionManager {
    /// Copies remote entries (files or whole folders) into `folder` on this Mac. Never
    /// overwrites a local file: a name that's taken gets " 2", " 3", ... added.
    public func download(_ entries: [SFTPEntry], to folder: URL) {
        for entry in entries {
            let local = Self.uniqueLocalURL(folder.appendingPathComponent(entry.filename))
            transfers.append(SFTPTransfer(direction: .download, name: entry.filename, localURL: local,
                                          remotePath: entry.path, totalBytes: entry.isDirectory ? nil : entry.size))
        }
        startTransferWorker()
    }

    /// Copies local files or folders into `remoteFolder` (the current folder by default),
    /// replacing remote files with the same name.
    public func upload(_ urls: [URL], to remoteFolder: String? = nil) {
        let folder = remoteFolder ?? currentPath
        for url in urls {
            transfers.append(SFTPTransfer(direction: .upload, name: url.lastPathComponent, localURL: url,
                                          remotePath: Self.join(folder, url.lastPathComponent)))
        }
        startTransferWorker()
    }

    public func cancelTransfer(_ id: UUID) {
        guard let index = transfers.firstIndex(where: { $0.id == id }) else { return }
        switch transfers[index].state {
        case .queued: transfers[index].state = .cancelled
        case .running: cancelledTransfers.insert(id)
        default: break
        }
    }

    public func clearFinishedTransfers() {
        transfers.removeAll { !$0.isActive }
    }

    /// Transfers run one at a time, in order.
    private func startTransferWorker() {
        guard transferWorker == nil else { return }
        let gen = generation
        transferWorker = Task { [weak self] in
            while let self, self.generation == gen,
                  let next = self.transfers.first(where: { $0.state == .queued }) {
                await self.run(next.id)
            }
            guard let self, self.generation == gen else { return }
            self.transferWorker = nil
            await self.refresh()
        }
    }

    private func update(_ id: UUID, _ change: (inout SFTPTransfer) -> Void) {
        guard let index = transfers.firstIndex(where: { $0.id == id }) else { return }
        change(&transfers[index])
    }

    private struct FileJob {
        let remote: String
        let local: URL
        let size: UInt64?
    }

    private func run(_ id: UUID) async {
        guard let transfer = transfers.first(where: { $0.id == id }) else { return }
        update(id) { $0.state = .running }
        do {
            switch transfer.direction {
            case .download: try await runDownload(transfer)
            case .upload: try await runUpload(transfer)
            }
            update(id) { $0.state = .finished }
            LoginTrace.event("sftp: \(transfer.direction == .download ? "downloaded" : "uploaded") "
                             + "\(LoginTrace.quoted(transfer.remotePath))")
        } catch is CancellationError {
            update(id) { $0.state = .cancelled }
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            update(id) { $0.state = .failed(message) }
            LoginTrace.event("sftp: transfer of \(LoginTrace.quoted(transfer.remotePath)) failed: \(message)", level: .error)
        }
        cancelledTransfers.remove(id)
    }

    private func checkCancelled(_ id: UUID) throws {
        if cancelledTransfers.contains(id) || Task.isCancelled { throw CancellationError() }
    }

    // MARK: Download

    private func runDownload(_ transfer: SFTPTransfer) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let attributes = try await sftp.getAttributes(at: transfer.remotePath)
        let isFolder = ((attributes.permissions ?? 0) & 0o170000) == 0o040000
        var jobs: [FileJob] = []
        if isFolder {
            try FileManager.default.createDirectory(at: transfer.localURL, withIntermediateDirectories: true)
            try await collectDownloads(remote: transfer.remotePath, local: transfer.localURL, into: &jobs, id: transfer.id)
        } else {
            jobs = [FileJob(remote: transfer.remotePath, local: transfer.localURL, size: attributes.size)]
        }
        let total = jobs.reduce(UInt64(0)) { $0 + ($1.size ?? 0) }
        update(transfer.id) {
            $0.totalBytes = total
            $0.fileCount = jobs.count
        }
        for job in jobs {
            try await downloadFile(job, id: transfer.id)
            update(transfer.id) { $0.filesDone += 1 }
        }
    }

    private func collectDownloads(remote: String, local: URL, into jobs: inout [FileJob], id: UUID) async throws {
        for entry in try await listEntries(at: remote) {
            try checkCancelled(id)
            let target = local.appendingPathComponent(entry.filename)
            if entry.isSymlink { continue } // not followed: it may point anywhere, even at a parent
            if entry.isDirectory {
                try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
                try await collectDownloads(remote: entry.path, local: target, into: &jobs, id: id)
            } else {
                jobs.append(FileJob(remote: entry.path, local: target, size: entry.size))
            }
        }
    }

    static let readChunk: UInt32 = 128 * 1024

    private func downloadFile(_ job: FileJob, id: UUID) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        guard FileManager.default.createFile(atPath: job.local.path, contents: nil) else {
            throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: job.local.path])
        }
        let output = try FileHandle(forWritingTo: job.local)
        let file = try await sftp.openFile(filePath: job.remote, flags: .read)
        var offset: UInt64 = 0
        do {
            while true {
                try checkCancelled(id)
                let chunk = try await file.read(from: offset, length: Self.readChunk)
                guard chunk.readableBytes > 0 else { break }
                try output.write(contentsOf: Data(chunk.readableBytesView))
                offset += UInt64(chunk.readableBytes)
                update(id) { $0.transferredBytes += UInt64(chunk.readableBytes) }
            }
            try? await file.close()
            try output.close()
        } catch {
            try? await file.close()
            try? output.close()
            try? FileManager.default.removeItem(at: job.local) // no half-written files left behind
            throw error
        }
    }

    // MARK: Upload

    private func runUpload(_ transfer: SFTPTransfer) async throws {
        let fm = FileManager.default
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: transfer.localURL.path, isDirectory: &isDirectory) else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSFilePathErrorKey: transfer.localURL.path])
        }
        var jobs: [FileJob] = []
        var folders: [String] = []
        if isDirectory.boolValue {
            folders.append(transfer.remotePath)
            let keys: [URLResourceKey] = [.isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey]
            let base = transfer.localURL.standardizedFileURL.path
            let enumerator = fm.enumerator(at: transfer.localURL, includingPropertiesForKeys: keys)
            while let url = enumerator?.nextObject() as? URL {
                let values = try url.resourceValues(forKeys: Set(keys))
                if values.isSymbolicLink == true { continue }
                let relative = String(url.standardizedFileURL.path.dropFirst(base.count + 1))
                let remote = Self.join(transfer.remotePath, relative)
                if values.isDirectory == true {
                    folders.append(remote)
                } else {
                    jobs.append(FileJob(remote: remote, local: url, size: values.fileSize.map(UInt64.init)))
                }
            }
        } else {
            let size = (try? fm.attributesOfItem(atPath: transfer.localURL.path)[.size] as? NSNumber)?.uint64Value
            jobs = [FileJob(remote: transfer.remotePath, local: transfer.localURL, size: size)]
        }
        update(transfer.id) {
            $0.totalBytes = jobs.reduce(UInt64(0)) { $0 + ($1.size ?? 0) }
            $0.fileCount = jobs.count
        }
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        for folder in folders {
            try checkCancelled(transfer.id)
            // It may exist already; a real problem shows when its files are written.
            try? await sftp.createDirectory(atPath: folder)
        }
        for job in jobs {
            try await uploadFile(job, id: transfer.id)
            update(transfer.id) { $0.filesDone += 1 }
        }
    }

    static let writeChunk = 1024 * 1024

    private func uploadFile(_ job: FileJob, id: UUID) async throws {
        guard let sftp = sftpClient else { throw SFTPManagerError.notConnected }
        let input = try FileHandle(forReadingFrom: job.local)
        defer { try? input.close() }
        let file = try await sftp.openFile(filePath: job.remote, flags: [.write, .create, .truncate])
        var offset: UInt64 = 0
        do {
            while true {
                try checkCancelled(id)
                guard let data = try input.read(upToCount: Self.writeChunk), !data.isEmpty else { break }
                try await file.write(ByteBuffer(data: data), at: offset)
                offset += UInt64(data.count)
                update(id) { $0.transferredBytes += UInt64(data.count) }
            }
            try await file.close()
        } catch {
            try? await file.close()
            if error is CancellationError { try? await sftp.remove(at: job.remote) }
            throw error
        }
    }

    /// `url`, or `name 2.ext`, `name 3.ext`, ... if that's taken.
    static func uniqueLocalURL(_ url: URL) -> URL {
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path) else { return url }
        let folder = url.deletingLastPathComponent()
        let ext = url.pathExtension
        let stem = url.deletingPathExtension().lastPathComponent
        for n in 2... {
            let candidate = folder.appendingPathComponent(ext.isEmpty ? "\(stem) \(n)" : "\(stem) \(n).\(ext)")
            if !fm.fileExists(atPath: candidate.path) { return candidate }
        }
        return url
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
