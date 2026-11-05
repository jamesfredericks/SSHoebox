import SwiftUI
import SSHoeboxCore
import CryptoKit

struct HostListView: View {
    @ObservedObject private var themeManager = ThemeManager.shared
    @StateObject private var viewModel: HostsViewModel
    @EnvironmentObject private var sessionRegistry: TerminalSessionRegistry
    @EnvironmentObject private var navigator: AppNavigator
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @State private var showingAddHost = false
    @State private var showingManageGroups = false
    @State private var showingImportSSHConfig = false
    @State private var showingImportCredentials = false
    @State private var hostToDelete: SavedHost?
    @State private var hostToEdit: SavedHost?

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
            .background(DesignSystem.Colors.background)

            Divider()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    let grouped = viewModel.hostsGrouped
                    if grouped.isEmpty {
                        emptyState
                    } else {
                        let favorites = viewModel.favoriteHosts
                        if !favorites.isEmpty {
                            favoritesSection(favorites)
                        }
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
        .sheet(item: $navigator.pendingNewHost, onDismiss: { viewModel.fetchHosts() }) { draft in
            AddHostSheet(viewModel: viewModel, draft: draft)
        }
        .sheet(item: $hostToEdit, onDismiss: { viewModel.fetchHosts() }) { host in
            EditHostSheet(viewModel: viewModel, host: host, vaultKey: vaultKey)
        }
        .navigationDestination(for: AppNavigator.HostRoute.self) { route in
            if let host = viewModel.hosts.first(where: { $0.id == route.hostId }) {
                HostDetailView(host: host, dbManager: dbManager, vaultKey: vaultKey, hostsViewModel: viewModel)
            } else {
                EmptyStateView(title: "Host Not Found", description: "This host was deleted.",
                               systemImage: "questionmark.folder")
            }
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
        .alert("Delete Host", isPresented: Binding(
            get: { hostToDelete != nil },
            set: { if !$0 { hostToDelete = nil } }
        ), presenting: hostToDelete) { host in
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) { viewModel.deleteHost(host) }
        } message: { host in
            Text("Are you sure you want to delete '\(host.decryptedName(using: vaultKey))'? Its credentials are deleted too, and open sessions to it are closed. This can't be undone.")
        }
        .onAppear {
            let registry = sessionRegistry
            viewModel.onHostDeleted = { [weak registry] hostId in registry?.removeStore(for: hostId) }
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
                    hostLink(host)
                }
            }
        }
    }

    private func favoritesSection(_ hosts: [SavedHost]) -> some View {
        let isCollapsed = viewModel.collapsedGroups.contains("__favorites__")
        return VStack(alignment: .leading, spacing: DesignSystem.Spacing.medium) {
            Button {
                viewModel.toggleCollapse(groupId: "__favorites__")
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: isCollapsed ? "chevron.right" : "chevron.down")
                        .font(.caption2)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    Image(systemName: "star.fill")
                        .font(.caption)
                        .foregroundStyle(Color.yellow.opacity(0.85))
                    Text("Favorites")
                        .font(DesignSystem.Typography.label())
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    Spacer()
                }
            }
            .buttonStyle(.plain)
            .padding(.top, DesignSystem.Spacing.large)
            if !isCollapsed {
                ForEach(hosts) { host in
                    hostLink(host)
                }
            }
        }
    }

    private func hostLink(_ host: SavedHost) -> some View {
        NavigationLink(value: AppNavigator.HostRoute(hostId: host.id)) {
            HostCard(host: host, vaultKey: vaultKey, options: viewModel.options(for: host),
                     jumpHostName: viewModel.options(for: host).jumpHostId.flatMap { id in
                         viewModel.hosts.first { $0.id == id }.map(viewModel.name(of:))
                     })
        }
        .buttonStyle(.plain)
        // .swipeActions only works on List rows, not inside this LazyVStack.
        .contextMenu {
            Button {
                navigator.open(hostId: host.id, action: .terminal)
            } label: {
                Label("Open Terminal", systemImage: "terminal")
            }
            Button {
                navigator.open(hostId: host.id, action: .newTerminal)
            } label: {
                Label("New Terminal Tab", systemImage: "plus.rectangle.on.rectangle")
            }
            Button {
                navigator.open(hostId: host.id, action: .files)
            } label: {
                Label("Browse Files (SFTP)", systemImage: "folder")
            }
            Divider()
            Button {
                viewModel.toggleFavorite(host)
            } label: {
                if viewModel.options(for: host).isFavorite {
                    Label("Remove from Favorites", systemImage: "star.slash")
                } else {
                    Label("Add to Favorites", systemImage: "star")
                }
            }
            Button {
                hostToEdit = host
            } label: {
                Label("Edit…", systemImage: "pencil")
            }
            Button {
                viewModel.duplicateHost(host)
            } label: {
                Label("Duplicate", systemImage: "plus.square.on.square")
            }
            Button {
                let user = host.decryptedUser(using: vaultKey)
                let link = "ssh://" + (user.isEmpty ? "" : "\(user)@") + host.decryptedHostname(using: vaultKey)
                    + (host.port == 22 ? "" : ":\(host.port)")
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(link, forType: .string)
            } label: {
                Label("Copy ssh:// Link", systemImage: "link")
            }
            Divider()
            Button(role: .destructive) {
                hostToDelete = host
            } label: {
                Label("Delete…", systemImage: "trash")
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
    var options = HostOptions()
    var jumpHostName: String? = nil
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
                HStack(spacing: 6) {
                    Text(host.decryptedName(using: vaultKey))
                        .font(DesignSystem.Typography.heading())
                        .foregroundStyle(DesignSystem.Colors.textPrimary)
                    if options.isFavorite {
                        Image(systemName: "star.fill")
                            .font(.caption2)
                            .foregroundStyle(Color.yellow.opacity(0.85))
                    }
                    ForEach(options.tags.prefix(4), id: \.self) { tag in
                        TagChip(tag: tag)
                    }
                }

                HStack(spacing: DesignSystem.Spacing.tight) {
                    Image(systemName: "network")
                        .font(.caption2)
                    Text("\(host.decryptedUser(using: vaultKey))@\(host.decryptedHostname(using: vaultKey))")
                        .font(DesignSystem.Typography.mono())
                }
                .foregroundStyle(DesignSystem.Colors.textSecondary)

                if jumpHostName != nil || !options.portForwards.isEmpty {
                    HStack(spacing: DesignSystem.Spacing.standard) {
                        if let jumpHostName {
                            Label("via \(jumpHostName)", systemImage: "arrow.triangle.branch")
                        }
                        if !options.portForwards.isEmpty {
                            Label("\(options.portForwards.count) tunnel\(options.portForwards.count == 1 ? "" : "s")",
                                  systemImage: "point.3.connected.trianglepath.dotted")
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.8))
                }

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
