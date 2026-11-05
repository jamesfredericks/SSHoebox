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
    @StateObject private var navigator: AppNavigator
    @ObservedObject private var themeManager = ThemeManager.shared

    static let mainWindowID = "main"

    init() {
        let viewModel = VaultViewModel()
        let sessionRegistry = TerminalSessionRegistry()
        let navigator = AppNavigator()
        // Wired here rather than in a view so it works even with the main window closed.
        viewModel.onLock = { [weak sessionRegistry, weak navigator] in
            sessionRegistry?.removeAll()
            navigator?.vaultDidLock()
        }
        _viewModel = StateObject(wrappedValue: viewModel)
        _sessionRegistry = StateObject(wrappedValue: sessionRegistry)
        _navigator = StateObject(wrappedValue: navigator)
    }

    var body: some Scene {
        // A single main window: the menu bar's "Open SSHoebox" reopens it after it's closed.
        Window("SSHoebox", id: Self.mainWindowID) {
            Group {
                if viewModel.isUnlocked {
                    MainView(viewModel: viewModel)
                        .preferredColorScheme(.dark)
                        .environmentObject(sessionRegistry)
                        .environmentObject(navigator)
                } else {
                    VaultUnlockView(viewModel: viewModel)
                        .preferredColorScheme(.dark)
                }
            }
            .onOpenURL { url in
                let deps = viewModel.getDependencies()
                navigator.handle(url: url, dbManager: deps?.0, vaultKey: deps?.1)
            }
        }
        .handlesExternalEvents(matching: ["ssh", "sshoebox"])
        .commands {
            CommandGroup(after: .newItem) {
                Button("Quick Connect…") { navigator.showQuickConnect = true }
                    .keyboardShortcut("k", modifiers: .command)
                    .disabled(!viewModel.isUnlocked)
            }
            CommandGroup(before: .windowList) {
                OpenLoginLogCommand()
                Divider()
            }
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

        Window("Login Log", id: LoginLogStore.windowID) {
            LoginLogView(viewModel: viewModel)
                .frame(minWidth: 640, minHeight: 360)
                .preferredColorScheme(.dark)
        }
        .defaultSize(width: 900, height: 520)

        MenuBarExtra("SSHoebox", systemImage: "server.rack") {
            MenuBarView(viewModel: viewModel)
                .environmentObject(sessionRegistry)
                .environmentObject(navigator)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Window → Login Log (⌥⌘L). A view of its own so it can read `openWindow`.
private struct OpenLoginLogCommand: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Login Log") { OpenLoginLogAction(openWindow: openWindow)() }
            .keyboardShortcut("l", modifiers: [.command, .option])
    }
}
