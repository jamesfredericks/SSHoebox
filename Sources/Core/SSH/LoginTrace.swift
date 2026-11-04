import Foundation
import os
import NIOSSH

/// Diagnostic log of one SSH or SFTP login attempt, for debugging failed logins.
///
/// Lines go to the macOS unified log, subsystem `com.sshoebox.app`, category `login`, each
/// prefixed with the attempt's id and the time since it started:
///
///     log stream --style compact --predicate 'subsystem == "com.sshoebox.app" AND category == "login"'
///     log show --last 1h --style compact --predicate 'subsystem == "com.sshoebox.app" AND category == "login"'
///
/// or Console.app filtered on that subsystem.
///
/// With `verbose` on, it also records the protocol itself, like `ssh -v`: the TCP connection,
/// version strings, both sides' algorithm lists and what was agreed, and every SSH message
/// sent and received up to and including the session's channel setup (see
/// `NIOSSHDebugObserver`). Those lines have level `.debug`.
///
/// What it records: the target, the username, the login method, what the server accepts,
/// what was offered, server prompts, key types and fingerprints, host key trust, timings and
/// errors. What it never records: passwords, private keys, passphrases, or anything the user
/// types at a prompt. Keep it that way: every message is logged as public text, so a secret
/// passed in would be readable by anyone with `log show` access.
public struct LoginTrace: Sendable {
    public enum Level: Sendable { case debug, info, error }
    public typealias Sink = @Sendable (_ level: Level, _ line: String) -> Void

    public static let subsystem = "com.sshoebox.app"
    private static let logger = Logger(subsystem: subsystem, category: "login")

    /// Writes to the unified log, and to `LoginLogBuffer.shared` for the app's Login Log window.
    /// `.notice` rather than `.info`, so lines are kept on disk and can be read with `log show`
    /// after the fact.
    public static let systemSink: Sink = { level, line in
        switch level {
        // Verbose lines are kept on disk too: they're what explains a failed login afterwards.
        case .debug, .info: logger.notice("\(line, privacy: .public)")
        case .error: logger.error("\(line, privacy: .public)")
        }
        LoginLogBuffer.shared.append(level: level, line: line)
    }

    /// Short random id that ties together the lines of one attempt.
    public let id: String
    private let started: ContinuousClock.Instant
    private let sink: Sink

    public init(sink: @escaping Sink = LoginTrace.systemSink) {
        self.id = String(UUID().uuidString.prefix(8)).lowercased()
        self.started = .now
        self.sink = sink
    }

    /// UserDefaults key for `verbose`.
    public static let verboseDefaultsKey = "loginLogVerbose"

    /// Whether new attempts record the protocol in detail (`ssh -v`). On unless turned off.
    public static var verbose: Bool {
        UserDefaults.standard.object(forKey: verboseDefaultsKey) as? Bool ?? true
    }

    /// Set as a connection's `SSHClientSettings.debugObserver` to record the protocol, or nil
    /// when verbose logging is off.
    public var protocolObserver: NIOSSHDebugObserver? {
        guard Self.verbose else { return nil }
        let trace = self
        return { line in trace.debug(line) }
    }

    public func debug(_ message: String) { sink(.debug, line(message)) }
    public func info(_ message: String) { sink(.info, line(message)) }
    public func error(_ message: String) { sink(.error, line(message)) }

    /// A line not tied to any attempt, such as a credential that couldn't be decrypted.
    public static func event(_ message: String, level: Level = .info, sink: Sink = LoginTrace.systemSink) {
        sink(level, "[-] \(message)")
    }

    /// Milliseconds since the attempt started.
    public var elapsedMilliseconds: Int64 {
        let (seconds, attoseconds) = (ContinuousClock.now - started).components
        return seconds * 1_000 + attoseconds / 1_000_000_000_000_000
    }

    private func line(_ message: String) -> String {
        "[\(id) +\(elapsedMilliseconds)ms] \(message)"
    }

    // MARK: - Formatting helpers

    /// The first line of an attempt.
    public func begin(_ kind: String, host: String, port: Int, username: String, method: String) {
        info("\(kind) login to \(host):\(port) as \(Self.quoted(username)) using \(method)")
        if username.isEmpty {
            error("username is empty")
        } else if username != username.trimmingCharacters(in: .whitespacesAndNewlines) {
            error("username has leading or trailing whitespace")
        }
        if host != host.trimmingCharacters(in: .whitespacesAndNewlines) {
            error("hostname has leading or trailing whitespace")
        }
    }

    /// `"text"`, with control characters escaped so a stray tab or newline shows up.
    static func quoted(_ text: String) -> String {
        "\"" + text.unicodeScalars.map { scalar in
            switch scalar {
            case "\n": return "\\n"
            case "\r": return "\\r"
            case "\t": return "\\t"
            case "\"": return "\\\""
            default:
                return scalar.properties.generalCategory == .control
                    ? String(format: "\\u{%04X}", scalar.value) : String(scalar)
            }
        }.joined() + "\""
    }

    /// The server's accepted methods, named as in OpenSSH's `AuthenticationMethods`.
    static func describe(_ methods: NIOSSHAvailableUserAuthenticationMethods) -> String {
        var names: [String] = []
        if methods.contains(.publicKey) { names.append("publickey") }
        if methods.contains(.password) { names.append("password") }
        if methods.contains(.keyboardInteractive) { names.append("keyboard-interactive") }
        if methods.contains(.hostBased) { names.append("hostbased") }
        return names.isEmpty ? "(none)" : names.joined(separator: ", ")
    }

    /// An error's type and full description, which is what tells NIOSSH failures apart.
    static func describe(_ error: Error) -> String {
        "\(type(of: error)): \(String(describing: error))"
    }
}
