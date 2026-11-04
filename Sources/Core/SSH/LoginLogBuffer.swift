import Foundation

/// One line of the login log, as shown in the app's Login Log window.
public struct LoginLogEntry: Identifiable, Sendable, Equatable {
    public let id: Int
    public let date: Date
    public let level: LoginTrace.Level
    /// `[<attempt id> +<ms>] message`, exactly as written to the unified log.
    public let line: String

    /// The attempt id from the line's prefix, or nil for lines not tied to an attempt.
    public var attemptID: String? {
        guard line.hasPrefix("["), let end = line.firstIndex(where: { $0 == " " || $0 == "]" }) else { return nil }
        let id = String(line[line.index(after: line.startIndex)..<end])
        return id == "-" ? nil : id
    }
}

/// The most recent login log lines of this app run, kept in memory so the app can show them
/// without reading the unified log. The unified log remains the full record.
///
/// The lines hold usernames and hostnames, so the app clears this when the vault locks.
public final class LoginLogBuffer: @unchecked Sendable {
    public static let shared = LoginLogBuffer()

    /// Posted on the main queue after lines are added or cleared, at most once per run loop turn.
    public static let didChange = Notification.Name("LoginLogBufferDidChange")

    public let capacity: Int
    private let lock = NSLock()
    private var stored: [LoginLogEntry] = []
    private var nextID = 0
    private var notifyPending = false

    public init(capacity: Int = 5_000) {
        self.capacity = capacity
    }

    public var entries: [LoginLogEntry] { lock.withLock { stored } }

    public func append(level: LoginTrace.Level, line: String, date: Date = Date()) {
        lock.withLock {
            stored.append(LoginLogEntry(id: nextID, date: date, level: level, line: line))
            nextID += 1
            if stored.count > capacity { stored.removeFirst(stored.count - capacity) }
        }
        scheduleNotification()
    }

    public func removeAll() {
        lock.withLock { stored.removeAll() }
        scheduleNotification()
    }

    private func scheduleNotification() {
        let shouldSchedule = lock.withLock { () -> Bool in
            guard !notifyPending else { return false }
            notifyPending = true
            return true
        }
        guard shouldSchedule else { return }
        DispatchQueue.main.async { [self] in
            lock.withLock { notifyPending = false }
            NotificationCenter.default.post(name: Self.didChange, object: self)
        }
    }
}
