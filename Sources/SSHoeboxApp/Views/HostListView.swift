import SwiftUI
import SSHoeboxCore
import CryptoKit

struct HostListView: View {
    @ObservedObject private var themeManager = ThemeManager.shared
    @StateObject private var viewModel: HostsViewModel
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @State private var showingAddHost = false
    
    init(dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.dbManager = dbManager
        self.vaultKey = vaultKey
        _viewModel = StateObject(wrappedValue: HostsViewModel(dbManager: dbManager, vaultKey: vaultKey))
    }
    
    var body: some View {
        ScrollView {
            LazyVStack(spacing: DesignSystem.Spacing.medium) {
                ForEach(viewModel.hosts) { host in
                    NavigationLink {
                        HostDetailView(host: host, dbManager: dbManager, vaultKey: vaultKey)
                    } label: {
                        HostCard(host: host, vaultKey: vaultKey)
                    }
                    .buttonStyle(.plain) // Remove default button/link styling
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        Button(role: .destructive) {
                            if let index = viewModel.hosts.firstIndex(where: { $0.id == host.id }) {
                                viewModel.deleteHost(at: IndexSet(integer: index))
                            }
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
            .padding(DesignSystem.Spacing.large)
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
        }
        .sheet(isPresented: $showingAddHost) {
            AddHostSheet(viewModel: viewModel)
        }
    }
}

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
        .shadow(color: isHovering ? Color.black.opacity(0.15) : Color.black.opacity(0.05), radius: isHovering ? 8 : 4, x: 0, y: isHovering ? 4 : 2)
        .animation(.spring(response: 0.3, dampingFraction: 0.6), value: isHovering)
        .onHover { hover in
            isHovering = hover
        }
    }
}
