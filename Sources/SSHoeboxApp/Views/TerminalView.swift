import SwiftUI
import SwiftTerm
import AppKit
import SSHoeboxCore

/// Shows a session's terminal view. The view belongs to the session (see `TerminalSession`),
/// so this only hosts it: whichever host appeared last takes it, and AppKit moves it out of
/// any previous one.
struct SessionTerminalHost: NSViewRepresentable {
    @ObservedObject var session: TerminalSession
    /// Give it keyboard focus when it appears (the selected tab, or the clicked tile).
    var focused = false

    final class Coordinator {
        var wasFocused = false
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> TerminalContainerView {
        let container = TerminalContainerView()
        container.adopt(session.terminal.view)
        return container
    }

    func updateNSView(_ container: TerminalContainerView, context: Context) {
        container.adopt(session.terminal.view)
        // Only when it becomes the focused one, so redraws don't take focus from text fields.
        if focused && !context.coordinator.wasFocused {
            let terminal = session.terminal
            DispatchQueue.main.async { terminal.focus() }
        }
        context.coordinator.wasFocused = focused
    }
}

/// Holds a terminal view that may move between containers.
final class TerminalContainerView: NSView {
    private weak var terminalView: NSView?

    func adopt(_ view: NSView) {
        terminalView = view
        guard view.superview !== self else { return }
        view.removeFromSuperview()
        view.frame = bounds
        view.autoresizingMask = [.width, .height]
        addSubview(view)
    }

    /// Takes the terminal back when shown again, in case another container held it meanwhile.
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window != nil, let terminalView, terminalView.superview !== self {
            adopt(terminalView)
        }
    }

    override func layout() {
        super.layout()
        terminalView?.frame = bounds
    }
}
