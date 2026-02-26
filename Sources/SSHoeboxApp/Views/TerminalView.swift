import SwiftUI
import SwiftTerm
import AppKit
import SSHoeboxCore

/// SwiftUI wrapper for SwiftTerm's TerminalView (NSView-based).
/// Handles remote SSH session I/O — forwards SSH output to the terminal display
/// and user keystrokes back to the SSH session.
struct RemoteTerminalView: NSViewRepresentable {
    
    @ObservedObject var session: SSHSessionManager
    var font: NSFont = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
    
    func makeNSView(context: Context) -> TerminalView {
        let termView = TerminalView(frame: .zero)
        termView.font = font
        // Dark terminal colors matching app theme
        termView.nativeForegroundColor = NSColor(calibratedRed: 0.85, green: 0.85, blue: 0.85, alpha: 1.0)
        termView.nativeBackgroundColor = NSColor(calibratedRed: 0.05, green: 0.05, blue: 0.08, alpha: 1.0)
        termView.terminalDelegate = context.coordinator
        context.coordinator.termView = termView
        
        // Wire session output → terminal display
        session.onOutput = { [weak coordinator = context.coordinator] data in
            DispatchQueue.main.async {
                coordinator?.termView?.feed(byteArray: ArraySlice(data))
            }
        }
        
        session.onDisconnect = { [weak coordinator = context.coordinator] in
            DispatchQueue.main.async {
                let msg = "\r\n\r\n\u{1B}[33m[Session ended. Close this tab to continue.]\u{1B}[0m\r\n"
                coordinator?.termView?.feed(text: msg)
            }
        }
        
        return termView
    }
    
    func updateNSView(_ nsView: TerminalView, context: Context) {
        nsView.font = font
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(session: session)
    }
    
    // MARK: - Coordinator
    
    class Coordinator: NSObject, TerminalViewDelegate {
        var session: SSHSessionManager
        weak var termView: TerminalView?
        
        init(session: SSHSessionManager) {
            self.session = session
        }
        
        // MARK: TerminalViewDelegate — required methods
        
        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            guard newCols > 0, newRows > 0 else { return }
            Task { @MainActor in session.resize(cols: newCols, rows: newRows) }
        }
        
        func setTerminalTitle(source: TerminalView, title: String) {}
        
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        
        func scrolled(source: TerminalView, position: Double) {}
        
        func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
            if let url = URL(string: link) {
                NSWorkspace.shared.open(url)
            }
        }
        
        func bell(source: TerminalView) {
            NSSound.beep()
        }
        
        func clipboardCopy(source: TerminalView, content: Data) {
            if let str = String(data: content, encoding: .utf8) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(str, forType: .string)
            }
        }
        
        func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
        
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
        
        /// Forward user keystrokes to the SSH session
        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            let bytes = Array(data)
            Task { @MainActor in session.send(Data(bytes)) }
        }
    }
}
