import Foundation
import CryptoKit

/// Session recordings, encrypted at rest.
///
/// A recording is what a terminal session showed, as plain text (escape sequences removed,
/// see `TerminalTextStripper`), sealed with a key derived from the vault key so it can only
/// be read in SSHoebox with the vault unlocked. Nothing about the session (not even the host
/// name) is visible in the file or its name.
///
/// File format (`.sshrec`):
///
///     "SSHREC01"            8 bytes, magic and version
///     salt                  16 random bytes; with the vault key gives this file's key
///     chunk*                uint32 big-endian length, then AES-256-GCM combined box
///                           (nonce, ciphertext, tag)
///
/// Each chunk is authenticated with the header, its index and whether it's the last one, so
/// chunks can't be reordered, dropped from the middle, or moved between files, and a file
/// cut short (the app quit mid-recording) is recognised as incomplete. A chunk's plaintext
/// starts with a kind byte: `M` (metadata JSON, always chunk 0), `T` (text), `E` (end JSON,
/// the last chunk).
public enum SessionRecording {
    public static let fileExtension = "sshrec"
    static let magic = Data("SSHREC01".utf8)
    static let saltLength = 16
    static let keyLabel = "com.sshoebox.recordings.v1"

    public static let directoryDefaultsKey = "sessionRecordingsDirectory"
    public static let autoRecordDefaultsKey = "recordAllSessions"

    /// The folder set in Preferences, or ~/Documents/SSHoebox Recordings.
    public static var directory: URL {
        if let path = UserDefaults.standard.string(forKey: directoryDefaultsKey), !path.isEmpty {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Documents")
        return documents.appendingPathComponent("SSHoebox Recordings", isDirectory: true)
    }

    /// Whether new terminal sessions start recording on their own.
    public static var recordsAutomatically: Bool {
        UserDefaults.standard.bool(forKey: autoRecordDefaultsKey)
    }

    /// What's stored about a recording (encrypted, in its first chunk).
    public struct Metadata: Codable, Equatable {
        public var hostName: String
        public var endpoint: String
        public var startedAt: Date
    }

    static func fileKey(vaultKey: SymmetricKey, salt: Data) -> SymmetricKey {
        let recordingsKey = CryptoManager.subkey(from: vaultKey, label: keyLabel)
        return HKDF<SHA256>.deriveKey(inputKeyMaterial: recordingsKey, salt: salt,
                                      info: Data("file".utf8), outputByteCount: 32)
    }

    static func associatedData(header: Data, index: UInt64, isFinal: Bool) -> Data {
        var data = header
        withUnsafeBytes(of: index.bigEndian) { data.append(contentsOf: $0) }
        data.append(isFinal ? 1 : 0)
        return data
    }

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    /// The recordings in the folder, newest first, each with its metadata if the vault key
    /// opens it. Others (another vault's, damaged) are listed without.
    public static func list(in folder: URL = directory, vaultKey: SymmetricKey) -> [Summary] {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: folder, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey])) ?? []
        return files.filter { $0.pathExtension == fileExtension }
            .map { url in
                let values = try? url.resourceValues(forKeys: [.fileSizeKey, .creationDateKey])
                return Summary(url: url, metadata: try? SessionRecordingReader.metadata(of: url, vaultKey: vaultKey),
                               fileSize: values?.fileSize ?? 0, created: values?.creationDate)
            }
            .sorted { ($0.metadata?.startedAt ?? $0.created ?? .distantPast) > ($1.metadata?.startedAt ?? $1.created ?? .distantPast) }
    }

    public struct Summary: Identifiable, Equatable {
        public var id: URL { url }
        public let url: URL
        /// Nil when this vault's key doesn't open the file.
        public let metadata: Metadata?
        public let fileSize: Int
        public let created: Date?
    }
}

/// Records a session's output to an encrypted `.sshrec` file.
///
/// Only output is recorded. What the user types appears only as far as the server echoes
/// it, so input the server doesn't echo (a password at a `sudo` prompt) isn't in it.
/// Text is sealed in chunks every few kilobytes or seconds, so a crash loses at most the
/// last moments; the plaintext never touches the disk.
public final class SessionRecorder {
    public let fileURL: URL
    public let metadata: SessionRecording.Metadata
    private let handle: FileHandle
    private let key: SymmetricKey
    private let header: Data
    private var index: UInt64 = 0
    private var stripper = TerminalTextStripper()
    private var pending = ""
    private var lastFlush = Date()
    private var finished = false

    static let flushBytes = 4096
    public static let flushInterval: TimeInterval = 2

    /// Creates `Recording <date>.sshrec` in `directory` (0700 folder, 0600 file).
    public init(directory: URL = SessionRecording.directory, hostName: String, endpoint: String,
                vaultKey: SymmetricKey, date: Date = Date()) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let stamp = Self.fileDateFormatter.string(from: date)
        var url = directory.appendingPathComponent("Recording \(stamp).\(SessionRecording.fileExtension)")
        var suffix = 2
        while fm.fileExists(atPath: url.path) {
            url = directory.appendingPathComponent("Recording \(stamp) \(suffix).\(SessionRecording.fileExtension)")
            suffix += 1
        }
        var salt = Data(count: SessionRecording.saltLength)
        let status = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, SessionRecording.saltLength, $0.baseAddress!) }
        guard status == errSecSuccess else { throw SecurityError.encryptionFailed }
        header = SessionRecording.magic + salt
        key = SessionRecording.fileKey(vaultKey: vaultKey, salt: salt)
        metadata = SessionRecording.Metadata(hostName: hostName, endpoint: endpoint, startedAt: date)

        guard fm.createFile(atPath: url.path, contents: header, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
        fileURL = url
        handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        try writeChunk(kind: "M", SessionRecording.encoder.encode(metadata), isFinal: false)
    }

    /// Adds terminal output.
    public func record(_ data: Data) {
        guard !finished else { return }
        pending += stripper.feed(data)
        if pending.utf8.count >= Self.flushBytes || Date().timeIntervalSince(lastFlush) >= Self.flushInterval {
            flush()
        }
    }

    /// Seals buffered text now (also called on a timer by the app while recording).
    public func flush() {
        guard !finished, !pending.isEmpty else { return }
        try? writeChunk(kind: "T", Data(pending.utf8), isFinal: false)
        pending = ""
        lastFlush = Date()
    }

    /// Seals what's left and the end marker, and closes the file.
    public func finish(date: Date = Date()) {
        guard !finished else { return }
        let rest = stripper.flush()
        if !rest.isEmpty { pending += rest + "\n" }
        flush()
        finished = true
        let end = (try? SessionRecording.encoder.encode(["endedAt": date])) ?? Data("{}".utf8)
        try? writeChunk(kind: "E", end, isFinal: true)
        try? handle.close()
    }

    deinit { finish() }

    private func writeChunk(kind: Character, _ body: Data, isFinal: Bool) throws {
        let plaintext = Data([kind.asciiValue!]) + body
        let aad = SessionRecording.associatedData(header: header, index: index, isFinal: isFinal)
        guard let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aad).combined else {
            throw SecurityError.encryptionFailed
        }
        var length = UInt32(sealed.count).bigEndian
        var record = Data(bytes: &length, count: 4)
        record.append(sealed)
        try handle.write(contentsOf: record)
        index += 1
    }

    private static let fileDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return formatter
    }()
}

/// Reads an encrypted recording with the vault key.
public enum SessionRecordingReader {
    public enum ReadError: LocalizedError {
        case notARecording
        case wrongKey

        public var errorDescription: String? {
            switch self {
            case .notARecording: return "This isn't an SSHoebox recording."
            case .wrongKey: return "This recording can't be opened with this vault (it was made with another vault, or it's damaged)."
            }
        }
    }

    public struct Contents: Equatable {
        public let metadata: SessionRecording.Metadata
        public let text: String
        public let endedAt: Date?
        /// False when the file stops before its end marker (the app quit while recording) or a
        /// chunk after the first fails to decrypt (damage). The text read up to there is kept.
        public let isComplete: Bool
    }

    public static func metadata(of url: URL, vaultKey: SymmetricKey) throws -> SessionRecording.Metadata {
        try read(url, vaultKey: vaultKey, metadataOnly: true).metadata
    }

    public static func read(_ url: URL, vaultKey: SymmetricKey) throws -> Contents {
        try read(url, vaultKey: vaultKey, metadataOnly: false)
    }

    private static func read(_ url: URL, vaultKey: SymmetricKey, metadataOnly: Bool) throws -> Contents {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let headerLength = SessionRecording.magic.count + SessionRecording.saltLength
        guard let header = try handle.read(upToCount: headerLength), header.count == headerLength,
              header.prefix(SessionRecording.magic.count) == SessionRecording.magic else {
            throw ReadError.notARecording
        }
        let key = SessionRecording.fileKey(vaultKey: vaultKey, salt: header.suffix(SessionRecording.saltLength))

        func nextChunk(_ index: UInt64) throws -> (kind: UInt8, body: Data, isFinal: Bool)? {
            guard let lengthBytes = try handle.read(upToCount: 4), lengthBytes.count == 4 else { return nil }
            let length = Int(lengthBytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) })
            guard length >= 29, length <= 16 * 1024 * 1024,
                  let sealed = try handle.read(upToCount: length), sealed.count == length,
                  let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }
            for isFinal in [false, true] {
                let aad = SessionRecording.associatedData(header: header, index: index, isFinal: isFinal)
                if let plain = try? AES.GCM.open(box, using: key, authenticating: aad), let kind = plain.first {
                    return (kind, plain.dropFirst(), isFinal)
                }
            }
            return nil
        }

        guard let first = try nextChunk(0), first.kind == UInt8(ascii: "M"),
              let metadata = try? SessionRecording.decoder.decode(SessionRecording.Metadata.self, from: first.body) else {
            throw ReadError.wrongKey
        }
        if metadataOnly { return Contents(metadata: metadata, text: "", endedAt: nil, isComplete: false) }

        var text = ""
        var endedAt: Date?
        var complete = false
        var index: UInt64 = 1
        while let chunk = try nextChunk(index) {
            index += 1
            switch chunk.kind {
            case UInt8(ascii: "T"):
                text += String(decoding: chunk.body, as: UTF8.self)
            case UInt8(ascii: "E"):
                endedAt = (try? SessionRecording.decoder.decode([String: Date].self, from: chunk.body))?["endedAt"]
                complete = chunk.isFinal
            default:
                break
            }
            if chunk.isFinal { break }
        }
        return Contents(metadata: metadata, text: text, endedAt: endedAt, isComplete: complete)
    }
}

/// Turns a terminal output stream into plain text: drops ANSI/VT escape sequences (CSI, OSC,
/// DCS and friends) and control characters, applies backspaces, and treats a carriage return
/// that isn't followed by a newline as overwriting the line (so progress bars leave only
/// their last state). Text is released a line at a time, so UTF-8 split across chunks is
/// kept whole.
public struct TerminalTextStripper {
    private enum State { case text, escape, csi, string, stringEscape, charset }

    private var state = State.text
    private var line: [UInt8] = []
    private var pendingCR = false

    public init() {}

    public mutating func feed(_ data: Data) -> String {
        var out: [UInt8] = []
        for byte in data {
            switch state {
            case .text:
                if pendingCR {
                    pendingCR = false
                    if byte == 0x0A {
                        out += line + [0x0A]
                        line.removeAll()
                        continue
                    }
                    line.removeAll()
                }
                switch byte {
                case 0x1B: state = .escape
                case 0x0A:
                    out += line + [0x0A]
                    line.removeAll()
                case 0x0D: pendingCR = true
                case 0x08:
                    // Remove one whole character, including its UTF-8 continuation bytes.
                    while let last = line.popLast(), last & 0xC0 == 0x80 {}
                case 0x09: line.append(byte)
                case 0x00..<0x20, 0x7F: break
                default: line.append(byte)
                }
            case .escape:
                switch byte {
                case UInt8(ascii: "["): state = .csi
                case UInt8(ascii: "]"), UInt8(ascii: "P"), UInt8(ascii: "X"), UInt8(ascii: "^"), UInt8(ascii: "_"):
                    state = .string
                case UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "*"), UInt8(ascii: "+"):
                    state = .charset
                default: state = .text
                }
            case .csi:
                if (0x40...0x7E).contains(byte) { state = .text }
            case .string:
                if byte == 0x07 { state = .text } else if byte == 0x1B { state = .stringEscape }
            case .stringEscape:
                state = byte == UInt8(ascii: "\\") ? .text : .string
            case .charset:
                state = .text
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// The unfinished last line, if any.
    public mutating func flush() -> String {
        defer { line.removeAll() }
        return String(decoding: line, as: UTF8.self)
    }
}
