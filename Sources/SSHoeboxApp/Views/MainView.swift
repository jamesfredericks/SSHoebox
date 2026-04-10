import SwiftUI
import SSHoeboxCore

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
                    Button { viewModel.lock() } label: {
                        Label("Lock Vault", systemImage: "lock.fill")
                    }
                    .help("Lock the vault")
                }
            }
        }
        .preferredColorScheme(themeManager.currentTheme.colorScheme)
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
