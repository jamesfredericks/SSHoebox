import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
@MainActor
struct SSHoeboxApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var viewModel: VaultViewModel
    @StateObject private var sessionRegistry: TerminalSessionRegistry
    @ObservedObject private var themeManager = ThemeManager.shared

    init() {
        let viewModel = VaultViewModel()
        let sessionRegistry = TerminalSessionRegistry()
        // Wired here rather than in a view so it works even with the main window closed.
        viewModel.onLock = { [weak sessionRegistry] in sessionRegistry?.removeAll() }
        _viewModel = StateObject(wrappedValue: viewModel)
        _sessionRegistry = StateObject(wrappedValue: sessionRegistry)
    }

    var body: some Scene {
        WindowGroup {
            if viewModel.isUnlocked {
                MainView(viewModel: viewModel)
                    .preferredColorScheme(.dark)
                    .environmentObject(sessionRegistry)
            } else {
                VaultUnlockView(viewModel: viewModel)
                    .preferredColorScheme(.dark)
            }
        }
        .commands {
            CommandGroup(after: .textEditing) {
                Button("Increase Font Size") {
                    ThemeManager.shared.increaseFontSize()
                }
                .keyboardShortcut("+", modifiers: .command)

                Button("Decrease Font Size") {
                    ThemeManager.shared.decreaseFontSize()
                }
                .keyboardShortcut("-", modifiers: .command)
            }
        }

        MenuBarExtra("SSHoebox", systemImage: "server.rack") {
            MenuBarView(viewModel: viewModel)
                .environmentObject(sessionRegistry)
        }
        .menuBarExtraStyle(.window)
    }
}
