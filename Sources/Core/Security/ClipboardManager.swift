import AppKit
import Foundation

/// Manages clipboard copies of sensitive secrets with an auto-clear timer.
/// Wire the `clipboardClearTimeout` property to the user's Preferences setting before calling `copy(_:)`.
@MainActor
public class ClipboardManager: ObservableObject {
    public static let shared = ClipboardManager()

    /// Seconds until clipboard is automatically cleared. 0 = never clear.
    public var clipboardClearTimeout: Int = ClipboardManager.savedClearTimeout

    /// The clear timeout saved in Preferences: 30s when unset, 0 when the user chose "Never".
    public static var savedClearTimeout: Int {
        UserDefaults.standard.object(forKey: "clipboardClearTimeout") == nil
            ? 30 : UserDefaults.standard.integer(forKey: "clipboardClearTimeout")
    }

    /// nspasteboard.org markers asking clipboard managers and history tools not to record
    /// the item (Concealed) and to treat it as short-lived (Transient).
    private static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    /// The secret currently on the clipboard, or `nil` when the clipboard is clear.
    @Published public var activeSecret: String? = nil

    /// Countdown value displayed in the UI (seconds remaining).
    @Published public var secondsRemaining: Int = 0

    private var countdownTimer: Timer?
    /// The last secret copied, tracked even with "Never" so locking the vault can still clear it.
    private var copiedSecret: String?
    private init() {}

    public var isActive: Bool { activeSecret != nil }

    /// Copies `secret` to the system clipboard and starts the auto-clear countdown.
    public func copy(_ secret: String) {
        cancelTimer()
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.declareTypes([.string, Self.concealedType, Self.transientType], owner: nil)
        pasteboard.setString(secret, forType: .string)
        pasteboard.setData(Data(), forType: Self.concealedType)
        pasteboard.setData(Data(), forType: Self.transientType)
        copiedSecret = secret

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
        if let secret = copiedSecret,
           NSPasteboard.general.string(forType: .string) == secret {
            NSPasteboard.general.clearContents()
        }
        copiedSecret = nil
        activeSecret = nil
    }

    private func cancelTimer() {
        countdownTimer?.invalidate()
        countdownTimer = nil
    }
}
