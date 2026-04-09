import Foundation
import Citadel
import Crypto
import NIOSSH
import NIOCore

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

    private var sshClient: SSHClient?
    private var sftpClient: SFTPClient?

    /// Set before calling connect to enable TOFU host key validation.
    public var knownHostRepository: KnownHostRepository?

    /// Set when a PEM key requires a passphrase. The UI observes this to show a prompt.
    @Published public var passphraseChallenge: SFTPPassphraseChallenge? = nil

    public init() {}

    // MARK: - Connect (password)

    public func connect(host: String, port: Int, username: String, password: String) async {
        await doConnect(host: host, port: port) { settings in
            var s = settings
            s.authenticationMethod = { .passwordBased(username: username, password: password) }
            return s
        }
    }

    // MARK: - Connect (PEM key — Ed25519 only for SFTP)

    public func connect(host: String, port: Int, username: String, pemKey: String, passphrase: String? = nil) async {
        let decryptionKey = passphrase.flatMap { $0.data(using: .utf8) }

        if let edKey = try? Curve25519.Signing.PrivateKey(sshEd25519: pemKey, decryptionKey: decryptionKey) {
            passphraseChallenge = nil
            await doConnect(host: host, port: port) { settings in
                var s = settings
                s.authenticationMethod = { .ed25519(username: username, privateKey: edKey) }
                return s
            }
            return
        }

        // Key is encrypted — request passphrase
        if SSHKeyParser.isEncryptedKey(pemKey) {
            if passphrase == nil {
                passphraseChallenge = SFTPPassphraseChallenge(
                    pemKey: pemKey, host: host, port: port, username: username
                )
            } else {
                connectionState = .failed("Incorrect passphrase")
                errorMessage = "The passphrase you entered is incorrect."
            }
            return
        }

        connectionState = .failed("Unsupported key type")
        errorMessage = "Only Ed25519 keys are currently supported for SFTP direct authentication."
    }

    // MARK: - Connection core

    private func doConnect(
        host: String,
        port: Int,
        configure: (SSHClientSettings) -> SSHClientSettings
    ) async {
        connectionState = .connecting
        isLoading = true
        errorMessage = nil

        let (validator, capturer) = buildValidator(for: host, port: port)
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .passwordBased(username: "", password: "") },
            hostKeyValidator: validator
        )
        settings.algorithms = .all
        settings = configure(settings)

        do {
            let client = try await SSHClient.connect(to: settings)

            // Persist TOFU key on first connection
            if let key = capturer?.capturedKey, let repo = knownHostRepository {
                let fingerprint = sshFingerprint(for: key)
                let openSSHStr  = String(openSSHPublicKey: key)
                let keyType     = String(openSSHStr.split(separator: " ").first ?? "unknown")
                let record = KnownHost(hostname: host, port: port, keyType: keyType,
                                       keyFingerprint: fingerprint, openSSHPublicKey: openSSHStr)
                try? repo.save(record)
            }

            let sftp = try await client.openSFTP()
            let home = (try? await sftp.getRealPath(atPath: ".")) ?? "/"

            self.sshClient = client
            self.sftpClient = sftp
            self.connectionState = .connected
            await loadDirectory(at: home)

        } catch is InvalidHostKey {
            connectionState = .failed("Host key mismatch")
            errorMessage = "Host key mismatch — remove the entry from Preferences → Known Hosts and reconnect."
            isLoading = false
        } catch {
            connectionState = .failed(error.localizedDescription)
            errorMessage = error.localizedDescription
            isLoading = false
        }
    }

    private func buildValidator(for host: String, port: Int) -> (SSHHostKeyValidator, CapturingHostKeyValidator?) {
        guard let repo = knownHostRepository else { return (.acceptAnything(), nil) }
        if let record = try? repo.find(hostname: host, port: port),
           let key = try? NIOSSHPublicKey(openSSHPublicKey: record.openSSHPublicKey) {
            return (.trustedKeys([key]), nil)
        }
        let capturer = CapturingHostKeyValidator()
        return (.custom(capturer), capturer)
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
        let ssh  = sshClient
        sftpClient = nil
        sshClient  = nil
        connectionState = .disconnected
        entries    = []
        currentPath = "/"
        Task {
            try? await sftp?.close()
            try? await ssh?.close()
        }
    }
}

// MARK: - Passphrase Challenge

public struct SFTPPassphraseChallenge: Identifiable {
    public let id = UUID()
    public let pemKey: String
    public let host: String
    public let port: Int
    public let username: String
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
