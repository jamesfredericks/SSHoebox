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
    @StateObject private var viewModel = VaultViewModel()
    @StateObject private var sessionRegistry = TerminalSessionRegistry()
    @ObservedObject private var themeManager = ThemeManager.shared

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
