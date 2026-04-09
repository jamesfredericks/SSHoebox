import AppKit
import Foundation

/// Manages clipboard copies of sensitive secrets with an auto-clear timer.
/// Wire the `clipboardClearTimeout` property to the user's Preferences setting before calling `copy(_:)`.
@MainActor
public class ClipboardManager: ObservableObject {
    public static let shared = ClipboardManager()

    /// Seconds until clipboard is automatically cleared. 0 = never clear.
    public var clipboardClearTimeout: Int = 30

    /// The secret currently on the clipboard, or `nil` when the clipboard is clear.
    @Published public var activeSecret: String? = nil

    /// Countdown value displayed in the UI (seconds remaining).
    @Published public var secondsRemaining: Int = 0

    private var countdownTimer: Timer?
    private init() {}

    public var isActive: Bool { activeSecret != nil }

    /// Copies `secret` to the system clipboard and starts the auto-clear countdown.
    public func copy(_ secret: String) {
        cancelTimer()
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(secret, forType: .string)

        guard clipboardClearTimeout > 0 else {
            activeSecret = nil
            return
        }

        activeSecret = secret
        secondsRemaining = clipboardClearTimeout

        countdownTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.secondsRemaining -= 1
                if self.secondsRemaining <= 0 {
                    self.clearNow()
                }
            }
        }
    }

    /// Immediately clears the clipboard and cancels the timer.
    public func clearNow() {
        cancelTimer()
        // Only clear if clipboard still holds our secret (user may have copied something else).
        if let secret = activeSecret,
           NSPasteboard.general.string(forType: .string) == secret {
            NSPasteboard.general.clearContents()
        }
        activeSecret = nil
    }

    private func cancelTimer() {
        countdownTimer?.invalidate()
        countdownTimer = nil
    }
}
