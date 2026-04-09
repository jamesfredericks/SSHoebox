import SwiftUI
import SSHoeboxCore
import CryptoKit

struct HostListView: View {
    @ObservedObject private var themeManager = ThemeManager.shared
    @StateObject private var viewModel: HostsViewModel
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @State private var showingAddHost = false
    @State private var showingManageGroups = false
    @State private var showingImportSSHConfig = false
    @State private var showingImportCredentials = false

    init(dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.dbManager = dbManager
        self.vaultKey = vaultKey
        _viewModel = StateObject(wrappedValue: HostsViewModel(dbManager: dbManager, vaultKey: vaultKey))
    }

    var body: some View {
        VStack(spacing: 0) {
            // Search bar
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 12))
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                TextField("Search hosts…", text: $viewModel.searchQuery)
                    .textFieldStyle(.plain)
                    .font(DesignSystem.Typography.body())
                if !viewModel.searchQuery.isEmpty {
                    Button {
                        viewModel.searchQuery = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, DesignSystem.Spacing.medium)
            .padding(.vertical, 8)
            .background(DesignSystem.Colors.surface)

            Divider()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    let grouped = viewModel.hostsGrouped
                    if grouped.isEmpty {
                        emptyState
                    } else {
                        ForEach(Array(grouped.enumerated()), id: \.offset) { _, section in
                            groupSection(section)
                        }
                    }
                }
                .padding(DesignSystem.Spacing.large)
            }
        }
        .background(DesignSystem.Colors.background)
        .navigationTitle("Hosts")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { showingAddHost = true }) {
                    Image(systemName: "plus")
                        .help("Add Host")
                }
            }
            ToolbarItem(placement: .automatic) {
                Button(action: { showingManageGroups = true }) {
                    Label("Groups", systemImage: "folder.badge.gearshape")
                        .help("Manage Groups")
                }
            }
            ToolbarItem(placement: .automatic) {
                Menu {
                    Button {
                        showingImportSSHConfig = true
                    } label: {
                        Label("Import from ~/.ssh/config", systemImage: "doc.text")
                    }
                    Button {
                        showingImportCredentials = true
                    } label: {
                        Label("Import from CSV / Bitwarden…", systemImage: "arrow.down.doc")
                    }
                } label: {
                    Image(systemName: "square.and.arrow.down")
                        .help("Import")
                }
            }
        }
        .sheet(isPresented: $showingAddHost, onDismiss: { viewModel.fetchHosts() }) {
            AddHostSheet(viewModel: viewModel)
        }
        .sheet(isPresented: $showingManageGroups, onDismiss: { viewModel.fetchHosts() }) {
            ManageGroupsSheet(viewModel: viewModel)
        }
        .sheet(isPresented: $showingImportSSHConfig, onDismiss: { viewModel.fetchHosts() }) {
            ImportSSHConfigSheet(viewModel: viewModel, vaultKey: vaultKey)
        }
        .sheet(isPresented: $showingImportCredentials, onDismiss: { viewModel.fetchHosts() }) {
            ImportCredentialsSheet(viewModel: viewModel)
        }
    }

    // MARK: - Group Section

    @ViewBuilder
    private func groupSection(_ section: (group: HostGroup?, hosts: [SavedHost])) -> some View {
        let groupId = section.group?.id ?? "__ungrouped__"
        let isCollapsed = viewModel.collapsedGroups.contains(groupId)

        VStack(alignment: .leading, spacing: DesignSystem.Spacing.medium) {
            // Section header (tappable to collapse)
            Button {
                viewModel.toggleCollapse(groupId: groupId)
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: isCollapsed ? "chevron.right" : "chevron.down")
                        .font(.caption2)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    Image(systemName: section.group != nil ? "folder.fill" : "tray.fill")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.accent.opacity(0.7))
                    Text(section.group?.name ?? "Ungrouped")
                        .font(DesignSystem.Typography.label())
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    Text("\(section.hosts.count)")
                        .font(.caption2)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(DesignSystem.Colors.surface)
                        .clipShape(Capsule())
                    Spacer()
                }
            }
            .buttonStyle(.plain)
            .padding(.top, DesignSystem.Spacing.large)

            // Host cards (hidden when collapsed)
            if !isCollapsed {
                ForEach(section.hosts) { host in
                    NavigationLink {
                        HostDetailView(host: host, dbManager: dbManager, vaultKey: vaultKey, hostsViewModel: viewModel)
                    } label: {
                        HostCard(host: host, vaultKey: vaultKey)
                    }
                    .buttonStyle(.plain)
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        Button(role: .destructive) {
                            viewModel.deleteHost(host)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
        }
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: DesignSystem.Spacing.medium) {
            if viewModel.searchQuery.isEmpty {
                Image(systemName: "server.rack")
                    .font(.system(size: 48))
                    .foregroundStyle(DesignSystem.Colors.accent.opacity(0.4))
                Text("No Hosts Yet")
                    .font(DesignSystem.Typography.heading())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                Text("Tap + to add your first host.")
                    .font(.caption)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            } else {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 40))
                    .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.4))
                Text("No results for \"\(viewModel.searchQuery)\"")
                    .font(DesignSystem.Typography.heading())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 80)
    }
}

// MARK: - Host Card

struct HostCard: View {
    let host: SavedHost
    let vaultKey: SymmetricKey
    @State private var isHovering = false

    var body: some View {
        HStack(spacing: DesignSystem.Spacing.medium) {
            // Protocol Icon
            ZStack {
                Circle()
                    .fill(DesignSystem.Colors.accent.opacity(0.1))
                    .frame(width: 40, height: 40)

                Text(host.protocolType.prefix(1).uppercased())
                    .font(DesignSystem.Typography.heading())
                    .foregroundStyle(DesignSystem.Colors.accent)
            }

            VStack(alignment: .leading, spacing: DesignSystem.Spacing.tight) {
                Text(host.decryptedName(using: vaultKey))
                    .font(DesignSystem.Typography.heading())
                    .foregroundStyle(DesignSystem.Colors.textPrimary)

                HStack(spacing: DesignSystem.Spacing.tight) {
                    Image(systemName: "network")
                        .font(.caption2)
                    Text("\(host.decryptedUser(using: vaultKey))@\(host.decryptedHostname(using: vaultKey))")
                        .font(DesignSystem.Typography.mono())
                }
                .foregroundStyle(DesignSystem.Colors.textSecondary)

                if let lastConnected = host.lastConnectedAt {
                    HStack(spacing: DesignSystem.Spacing.tight) {
                        Image(systemName: "clock")
                            .font(.caption2)
                        Text(lastConnected.formatted(.relative(presentation: .named)))
                            .font(.caption2)
                    }
                    .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.6))
                }
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.5))
        }
        .padding(DesignSystem.Spacing.medium)
        .background(DesignSystem.Colors.surface)
        .cornerRadius(DesignSystem.Radius.md)
        .overlay(
            RoundedRectangle(cornerRadius: DesignSystem.Radius.md)
                .stroke(DesignSystem.Colors.border, lineWidth: 1)
        )
        .scaleEffect(isHovering ? 1.02 : 1.0)
        .shadow(color: isHovering ? Color.black.opacity(0.15) : Color.black.opacity(0.05),
                radius: isHovering ? 8 : 4, x: 0, y: isHovering ? 4 : 2)
        .animation(.spring(response: 0.3, dampingFraction: 0.6), value: isHovering)
        .onHover { hover in isHovering = hover }
    }
}
