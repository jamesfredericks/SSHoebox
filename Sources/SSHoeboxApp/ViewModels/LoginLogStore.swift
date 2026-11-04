import Foundation
import Combine
import SSHoeboxCore

/// Feeds the Login Log window from `LoginLogBuffer.shared`, and carries the attempt a
/// "View Login Log" button asked to show.
@MainActor
final class LoginLogStore: ObservableObject {
    static let shared = LoginLogStore()
    static let windowID = "login-log"

    @Published private(set) var entries: [LoginLogEntry] = []
    /// When set, the window shows only this attempt's lines.
    @Published var focusedAttemptID: String?

    private let buffer: LoginLogBuffer
    private var observer: NSObjectProtocol?

    init(buffer: LoginLogBuffer = .shared) {
        self.buffer = buffer
        entries = buffer.entries
        observer = NotificationCenter.default.addObserver(
            forName: LoginLogBuffer.didChange, object: buffer, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.reload() }
        }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    func reload() {
        entries = buffer.entries
    }

    func clear() {
        buffer.removeAll()
        focusedAttemptID = nil
        reload()
    }

    /// The lines to show for the current filters.
    func visibleEntries(search: String, errorsOnly: Bool) -> [LoginLogEntry] {
        entries.filter { entry in
            (focusedAttemptID == nil || entry.attemptID == focusedAttemptID)
                && (!errorsOnly || entry.level == .error)
                && (search.isEmpty || entry.line.localizedCaseInsensitiveContains(search))
        }
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return formatter
    }()

    static func timestamp(_ date: Date) -> String {
        timestampFormatter.string(from: date)
    }

    private static func label(_ level: LoginTrace.Level) -> String {
        switch level {
        case .debug: return "debug"
        case .info: return "     "
        case .error: return "ERROR"
        }
    }

    /// Plain text of `entries`, one line each, for the clipboard or a file.
    static func text(of entries: [LoginLogEntry]) -> String {
        entries.map { entry in
            "\(timestamp(entry.date)) \(label(entry.level)) \(entry.line)"
        }.joined(separator: "\n") + "\n"
    }
}
