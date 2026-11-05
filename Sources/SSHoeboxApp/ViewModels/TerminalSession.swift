import Foundation
import AppKit
import Combine
import SwiftTerm
import CryptoKit
import SSHoeboxCore

/// One terminal tab: an SSH session and the terminal view showing it. The session owns its
/// view, so the screen and scrollback survive navigating away and back, and the same session
/// can be shown in a host's tabs, a split or the Sessions workspace (one place at a time).
@MainActor
final class TerminalSession: ObservableObject, Identifiable {
    let id = UUID()
    let hostId: String
    let hostName: String
    let title: String
    let manager: SSHSessionManager
    let terminal: SessionTerminal

    /// Routes typed input (for broadcasting). Set by the registry.
    weak var registry: TerminalSessionRegistry?

    @Published private(set) var recorder: SessionRecorder?
    @Published private(set) var recordingError: String?
    /// Recordings are sealed with a key derived from this; dropped with the session on lock.
    private let vaultKey: SymmetricKey
    /// Seals buffered output every couple of seconds, so little is lost if the app quits.
    private var flushTimer: Timer?

    init(hostId: String, hostName: String, title: String, manager: SSHSessionManager, vaultKey: SymmetricKey) {
        self.vaultKey = vaultKey
        self.hostId = hostId
        self.hostName = hostName
        self.title = title
        self.manager = manager
        self.terminal = SessionTerminal()
        terminal.session = self
        manager.onOutput = { [weak self] data in
            self?.terminal.feed(data)
            self?.recorder?.record(data)
        }
        manager.onDisconnect = { [weak self] in
            let message = "\r\n\r\n\u{1B}[33m[Session ended. Reconnect, or close this tab.]\u{1B}[0m\r\n"
            self?.terminal.feed(Data(message.utf8))
        }
    }

    var isRecording: Bool { recorder != nil }

    /// What the user typed, or a snippet: to this session, or to every session in the
    /// broadcast group if this one is in it.
    func sendInput(_ data: Data) {
        if let registry, registry.isBroadcasting(self) {
            registry.broadcast(data)
        } else {
            manager.send(data)
        }
    }

    /// Sends a snippet's command: typed as is, then Return unless `run` is false.
    func sendCommand(_ command: String, run: Bool = true) {
        let text = command.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r")
        sendInput(Data((text + (run ? "\r" : "")).utf8))
        terminal.focus()
    }

    // MARK: - Recording

    func startRecording() {
        guard recorder == nil else { return }
        do {
            let recorder = try SessionRecorder(hostName: hostName, endpoint: manager.endpoint ?? hostName,
                                               vaultKey: vaultKey)
            self.recorder = recorder
            recordingError = nil
            flushTimer = Timer.scheduledTimer(withTimeInterval: SessionRecorder.flushInterval, repeats: true) { [weak recorder] _ in
                recorder?.flush()
            }
            LoginTrace.event("recording: \(hostName) \(title) to \(recorder.fileURL.path) (encrypted)")
        } catch {
            recordingError = error.localizedDescription
            LoginTrace.event("recording: could not start for \(hostName): \(error.localizedDescription)", level: .error)
        }
    }

    func stopRecording() {
        flushTimer?.invalidate()
        flushTimer = nil
        recorder?.finish()
        recorder = nil
    }

    /// Ends the session for good (tab closed or vault locked).
    func close() {
        stopRecording()
        manager.disconnect()
    }
}

/// The SwiftTerm view of a session, and its delegate.
@MainActor
final class SessionTerminal: NSObject, TerminalViewDelegate {
    let view: TerminalView
    weak var session: TerminalSession?
    private var fontObserver: AnyCancellable?

    override init() {
        view = TerminalView(frame: NSRect(x: 0, y: 0, width: 640, height: 400))
        super.init()
        view.nativeForegroundColor = NSColor(calibratedRed: 0.85, green: 0.85, blue: 0.85, alpha: 1.0)
        view.nativeBackgroundColor = NSColor(calibratedRed: 0.05, green: 0.05, blue: 0.08, alpha: 1.0)
        view.terminalDelegate = self
        fontObserver = ThemeManager.shared.$terminalFontSize
            .removeDuplicates()
            .sink { [weak self] size in
                self?.view.font = NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
            }
    }

    func feed(_ data: Data) {
        view.feed(byteArray: ArraySlice(data))
    }

    /// Makes this terminal take keyboard input.
    func focus() {
        view.window?.makeFirstResponder(view)
    }

    // MARK: TerminalViewDelegate

    nonisolated func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
        guard newCols > 0, newRows > 0 else { return }
        MainActor.assumeIsolated { self.session?.manager.resize(cols: newCols, rows: newRows) }
    }

    nonisolated func setTerminalTitle(source: TerminalView, title: String) {}

    nonisolated func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}

    nonisolated func scrolled(source: TerminalView, position: Double) {}

    nonisolated func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
        // Only web links: a remote program mustn't open arbitrary URL schemes on this Mac.
        guard let url = URL(string: link), let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme) else { return }
        DispatchQueue.main.async { NSWorkspace.shared.open(url) }
    }

    nonisolated func bell(source: TerminalView) {
        DispatchQueue.main.async { NSSound.beep() }
    }

    /// OSC 52: a remote program asks to set the clipboard. Only allowed when the user turned
    /// it on in Preferences, since it lets any server replace what's on the clipboard.
    nonisolated func clipboardCopy(source: TerminalView, content: Data) {
        guard UserDefaults.standard.bool(forKey: "terminalAllowOSC52"),
              let text = String(data: content, encoding: .utf8) else { return }
        DispatchQueue.main.async {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        }
    }

    nonisolated func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}

    nonisolated func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}

    /// Keystrokes and pastes from the terminal view.
    nonisolated func send(source: TerminalView, data: ArraySlice<UInt8>) {
        let bytes = Data(data)
        // AppKit calls this on the main thread; handling it right here keeps keystrokes in order.
        MainActor.assumeIsolated { self.session?.sendInput(bytes) }
    }
}
