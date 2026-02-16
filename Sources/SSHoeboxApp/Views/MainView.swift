import SwiftUI
import SSHoeboxCore

struct MainView: View {
    @ObservedObject var viewModel: VaultViewModel
    @ObservedObject private var themeManager = ThemeManager.shared
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
                // Background that fills the whole column including title area
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
                
                // Full-height rounded neon border
                RoundedRectangle(cornerRadius: 12)
                    .stroke(DesignSystem.Colors.border, lineWidth: 1)
                    .padding(2)
                    .ignoresSafeArea()
                    .allowsHitTesting(false) // Don't block traffic lights or list items
            }
            .preferredColorScheme(themeManager.currentTheme.colorScheme)
            .tint(DesignSystem.Colors.accent)
        } detail: {
            // FIX: Wrap detail in NavigationStack to prevent UI lockup and fix macOS navigation
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
                        BackupView(dbManager: db)
                    }
                case .preferences:
                    PreferencesView()
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
    }
}
