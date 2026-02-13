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
    
    var body: some Scene {
        WindowGroup {
            if viewModel.isUnlocked {
                MainView(viewModel: viewModel)
                    .preferredColorScheme(.dark)
            } else {
                VaultUnlockView(viewModel: viewModel)
                    .preferredColorScheme(.dark)
            }
        }
    }
}
