import SwiftUI
import AppKit
import SSHoeboxCore

// Neutralizes the NSVisualEffectView card that NavigationSplitView injects behind
// the sidebar, and removes the toolbar separator line.
//
// Key fixes vs. prior attempt:
//  1. Searches DOWN from window.contentView (not up from self) — the WindowStyler's
//     own NSView is placed OUTSIDE the NSSplitView by SwiftUI, so walking up never
//     finds it.
//  2. Neutralizes (material + layer props) instead of isHidden = true — hiding a
//     parent also hides all its children, including our content.
//  3. Sets window.backgroundColor so the neutralized material matches our theme.
//  4. Retries at several delays to handle SwiftUI's async hierarchy construction.
private struct WindowStyler: NSViewRepresentable {
    let backgroundColor: Color

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        for delay in [0.0, 0.1, 0.3, 0.6] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                Self.apply(from: view, color: backgroundColor)
            }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async { Self.apply(from: nsView, color: backgroundColor) }
    }

    private static func apply(from view: NSView, color: Color) {
        guard let window = view.window else { return }

        // Remove the hairline below the toolbar
        window.titlebarSeparatorStyle = .none
        // Set the window background so .windowBackground material matches our theme
        window.backgroundColor = NSColor(color)

        // Search DOWN from the window content view for the NSSplitView
        guard let splitView = findFirst(NSSplitView.self, in: window.contentView),
              let sidebarColumn = splitView.subviews.first else { return }

        // Neutralize every NSVisualEffectView in the sidebar column (card background)
        neutralize(in: sidebarColumn, color: color, depth: 0)
    }

    /// Recursively neutralizes NSVisualEffectView instances without hiding them
    /// (hiding a parent would hide children too).
    private static func neutralize(in view: NSView, color: Color, depth: Int) {
        guard depth < 6 else { return }
        if let fx = view as? NSVisualEffectView {
            fx.material = .windowBackground
            fx.blendingMode = .withinWindow
            fx.state = .active
            fx.wantsLayer = true
            fx.layer?.cornerRadius = 0
            fx.layer?.shadowOpacity = 0
            fx.layer?.borderWidth = 0
            fx.layer?.backgroundColor = NSColor(color).cgColor
        }
        view.subviews.forEach { neutralize(in: $0, color: color, depth: depth + 1) }
    }

    /// BFS/DFS helper: finds the first view of a given type in the subtree.
    private static func findFirst<T: NSView>(_ type: T.Type, in view: NSView?) -> T? {
        guard let view else { return nil }
        if let match = view as? T { return match }
        for sub in view.subviews {
            if let found = findFirst(type, in: sub) { return found }
        }
        return nil
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
                    Color.clear.frame(height: DesignSystem.Spacing.large)
                }

                // Custom neon border
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
                    Button { viewModel.lock() } label: {
                        Label("Lock Vault", systemImage: "lock.fill")
                    }
                    .help("Lock the vault")
                }
            }
        }
        .toolbarBackground(DesignSystem.Colors.background, for: .windowToolbar)
        .toolbarBackground(.visible, for: .windowToolbar)
        .preferredColorScheme(themeManager.currentTheme.colorScheme)
        // Pass current background color so WindowStyler stays in sync with theme changes
        .background(WindowStyler(backgroundColor: DesignSystem.Colors.background))
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
