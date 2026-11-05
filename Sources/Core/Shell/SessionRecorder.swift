import Foundation

/// Records what a terminal session shows to a plain-text file, like `script(1)` but with the
/// escape sequences (colors, cursor movement) taken out so it reads in any editor.
///
/// Only the session's output is recorded. What the user types appears only as far as the
/// server echoes it, so input the server doesn't echo, such as a password at a `sudo` prompt,
/// isn't in the file. Anything the server prints is, so the file is written readable by the
/// user only (0600), in a folder that is too (0700).
public final class SessionRecorder {
    public let fileURL: URL
    private let handle: FileHandle
    private var stripper = TerminalTextStripper()
    private var finished = false

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

    /// Creates `<host> <date>.txt` in `directory` and writes a header naming the session.
    public init(directory: URL = SessionRecorder.directory, hostName: String, endpoint: String,
                date: Date = Date()) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let stamp = Self.fileDateFormatter.string(from: date)
        let safeName = hostName.map { "/:\\".contains($0) ? "-" : $0 }.reduce(into: "") { $0.append($1) }
        var url = directory.appendingPathComponent("\(safeName) \(stamp).txt")
        var suffix = 2
        while fm.fileExists(atPath: url.path) {
            url = directory.appendingPathComponent("\(safeName) \(stamp) \(suffix).txt")
            suffix += 1
        }
        guard fm.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
        fileURL = url
        handle = try FileHandle(forWritingTo: url)
        let header = """
        SSHoebox session recording
        Host:    \(hostName) (\(endpoint))
        Started: \(Self.headerDateFormatter.string(from: date))
        Output only: input the server doesn't echo (such as passwords) isn't recorded.
        ----------------------------------------------------------------------

        """
        try handle.write(contentsOf: Data(header.utf8))
    }

    /// Adds terminal output.
    public func record(_ data: Data) {
        guard !finished else { return }
        let text = stripper.feed(data)
        if !text.isEmpty { try? handle.write(contentsOf: Data(text.utf8)) }
    }

    /// Writes what's left and a closing line, and closes the file.
    public func finish(date: Date = Date()) {
        guard !finished else { return }
        finished = true
        let rest = stripper.flush()
        let footer = (rest.isEmpty ? "" : rest + "\n")
            + "\n----------------------------------------------------------------------\n"
            + "Ended:   \(Self.headerDateFormatter.string(from: date))\n"
        try? handle.write(contentsOf: Data(footer.utf8))
        try? handle.close()
    }

    deinit { finish() }

    private static let fileDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return formatter
    }()

    private static let headerDateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = .current
        return formatter
    }()
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
