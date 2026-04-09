import SwiftUI
import AppKit
import SSHoeboxCore

// Removes the thin separator line macOS draws between the toolbar and window content.
private struct TitlebarSeparatorRemover: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            view.window?.titlebarSeparatorStyle = .none
        }
        return view
    }
    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            nsView.window?.titlebarSeparatorStyle = .none
        }
    }
}

struct MainView: View {
    @ObservedObject var viewModel: VaultViewModel
    @ObservedObject private var themeManager = ThemeManager.shared
    @EnvironmentObject private var sessionRegistry: TerminalSessionRegistry
    @State private var selection: SidebarItem? = .hosts

    enum SidebarItem: Hashable {
        case hosts
        case generator
        case backups
        case preferences
    }

    var body: some View {
        NavigationSplitView {
            ZStack {
                DesignSystem.Colors.background
                    .ignoresSafeArea()

                List(selection: $selection) {
                    Section("Vault") {
                        NavigationLink(value: SidebarItem.hosts) {
                            Label("Hosts", systemImage: "server.rack")
                                .foregroundColor(DesignSystem.Colors.textPrimary)
                        }
                    }

                    Section("Tools") {
                        NavigationLink(value: SidebarItem.generator) {
                            Label("Generator", systemImage: "wand.and.stars")
                                .foregroundColor(DesignSystem.Colors.textPrimary)
                        }
                    }

                    Section("Settings") {
                        NavigationLink(value: SidebarItem.backups) {
                            Label("Backups", systemImage: "externaldrive.badge.icloud")
                                .foregroundColor(DesignSystem.Colors.textPrimary)
                        }

                        NavigationLink(value: SidebarItem.preferences) {
                            Label("Preferences", systemImage: "gear")
                                .foregroundColor(DesignSystem.Colors.textPrimary)
                        }
                    }
                }
                .listStyle(.sidebar)
                .scrollContentBackground(.hidden)
                .safeAreaInset(edge: .top) {
                    // Push content down so the first section header clears the border
                    Color.clear.frame(height: DesignSystem.Spacing.large)
                }

                // Sidebar border
                RoundedRectangle(cornerRadius: 12)
                    .stroke(DesignSystem.Colors.border, lineWidth: 1)
                    .padding(2)
                    .allowsHitTesting(false)
            }
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .preferredColorScheme(themeManager.currentTheme.colorScheme)
            .tint(DesignSystem.Colors.accent)
        } detail: {
            NavigationStack {
                switch selection {
                case .hosts:
                    if let deps = viewModel.getDependencies() {
                        HostListView(dbManager: deps.0, vaultKey: deps.1)
                    } else {
                        ProgressView()
                    }
                case .generator:
                    GeneratorView()
                case .backups:
                    if let db = viewModel.dbManager {
                        BackupView(dbManager: db, vaultViewModel: viewModel)
                    }
                case .preferences:
                    PreferencesView(viewModel: viewModel)
                case .none:
                    Text("Select an item")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
            }
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button {
                        viewModel.lock()
                    } label: {
                        Label("Lock Vault", systemImage: "lock.fill")
                    }
                    .help("Lock the vault")
                }
            }
        }
        .toolbarBackground(DesignSystem.Colors.background, for: .windowToolbar)
        .toolbarBackground(.visible, for: .windowToolbar)
        .preferredColorScheme(themeManager.currentTheme.colorScheme)
        .background(TitlebarSeparatorRemover())
        .onAppear {
            let registry = sessionRegistry
            viewModel.activeSessionCount = { registry.totalActiveConnections }
            let timeout = UserDefaults.standard.integer(forKey: "clipboardClearTimeout")
            ClipboardManager.shared.clipboardClearTimeout = timeout == 0 ? 30 : timeout
        }
        .overlay(alignment: .bottom) {
            ClipboardStatusBadge()
                .animation(.spring(response: 0.3, dampingFraction: 0.8), value: ClipboardManager.shared.isActive)
        }
    }
}
