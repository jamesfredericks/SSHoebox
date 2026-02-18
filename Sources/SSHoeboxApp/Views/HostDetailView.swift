import SwiftUI
import SSHoeboxCore
import CryptoKit

struct HostDetailView: View {
    @ObservedObject private var themeManager = ThemeManager.shared
    @Environment(\.dismiss) var dismiss
    let host: SavedHost
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @StateObject private var viewModel: CredentialsViewModel
    @StateObject private var hostsViewModel: HostsViewModel
    @State private var showingAddCredential = false
    @State private var showingEditHost = false
    @State private var showingDeleteAlert = false
    @State private var credentialToEdit: Credential? = nil
    @State private var copiedId: String? = nil
    @State private var selectedTab: HostTab = .credentials
    
    enum HostTab {
        case credentials, terminal
    }
    
    init(host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.host = host
        self.dbManager = dbManager
        self.vaultKey = vaultKey
        _viewModel = StateObject(wrappedValue: CredentialsViewModel(dbManager: dbManager, vaultKey: vaultKey, hostId: host.id))
        _hostsViewModel = StateObject(wrappedValue: HostsViewModel(dbManager: dbManager, vaultKey: vaultKey))
    }
    
    var body: some View {
        VStack(spacing: 0) {
            heroHeader
            if selectedTab == .credentials {
                contentList
            } else {
                TerminalTabView(host: host, dbManager: dbManager, vaultKey: vaultKey)
            }
        }
        .navigationTitle("") // Hide default title since we have a hero
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("Connect (SSH)") { connect(protocol: "ssh") }
                    Button("Connect (SFTP)") { connect(protocol: "sftp") }
                } label: {
                    Image(systemName: "play.fill")
                }
            }
            
            ToolbarItem(placement: .automatic) {
                Button {
                    showingEditHost = true
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
            }
            
            ToolbarItem(placement: .automatic) {
                Button(role: .destructive) {
                    showingDeleteAlert = true
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
        .sheet(isPresented: $showingAddCredential) {
            AddCredentialSheet(viewModel: viewModel)
        }
        .sheet(isPresented: $showingEditHost) {
            EditHostSheet(viewModel: hostsViewModel, host: host, vaultKey: vaultKey)
        }
        .sheet(item: $credentialToEdit) { credential in
            EditCredentialSheet(viewModel: viewModel, credential: credential, vaultKey: vaultKey)
        }
        .alert("Delete Host", isPresented: $showingDeleteAlert) {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) {
                if let index = hostsViewModel.hosts.firstIndex(where: { $0.id == host.id }) {
                    hostsViewModel.deleteHost(at: IndexSet(integer: index))
                    dismiss()
                }
            }
        } message: {
            Text("Are you sure you want to delete '\(host.decryptedName(using: vaultKey))'? This action cannot be undone.")
        }
    }
    
    // MARK: - Subviews
    
    private var heroHeader: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: DesignSystem.Spacing.large) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: DesignSystem.Spacing.tight) {
                        Text(host.decryptedName(using: vaultKey))
                            .font(DesignSystem.Typography.hero())
                        
                        HStack(spacing: DesignSystem.Spacing.standard) {
                            Text(host.protocolType.uppercased())
                                .font(DesignSystem.Typography.label())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(DesignSystem.Colors.accent.opacity(0.1))
                                .foregroundStyle(DesignSystem.Colors.accent)
                                .cornerRadius(DesignSystem.Radius.sm)
                            
                            Text("\(host.decryptedUser(using: vaultKey))@\(host.decryptedHostname(using: vaultKey)):\(host.port)")
                                .font(DesignSystem.Typography.mono())
                                .foregroundStyle(DesignSystem.Colors.textSecondary)
                        }
                    }
                    
                    Spacer()
                    
                    // Primary Action
                    Button("Connect") {
                        connect(protocol: host.protocolType)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }
                
                Divider()
            }
            .padding(DesignSystem.Spacing.large)
            
            // Tab picker
            Picker("", selection: $selectedTab) {
                Label("Credentials", systemImage: "key").tag(HostDetailView.HostTab.credentials)
                Label("Terminal", systemImage: "terminal").tag(HostDetailView.HostTab.terminal)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, DesignSystem.Spacing.large)
            .padding(.vertical, DesignSystem.Spacing.standard)
        }
        .background(DesignSystem.Colors.surface)
    }
    
    private var contentList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DesignSystem.Spacing.large) {
                // Credentials Section
                VStack(alignment: .leading, spacing: DesignSystem.Spacing.medium) {
                    credentialsHeader
                    credentialsGrid
                }
            }
            .padding(DesignSystem.Spacing.large)
        }
        .background(DesignSystem.Colors.background)
    }
    
    private var credentialsHeader: some View {
        HStack {
            Text("CREDENTIALS")
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            
            Spacer()
            
            Button {
                showingAddCredential = true
            } label: {
                Label("Add", systemImage: "plus")
                    .font(DesignSystem.Typography.label())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(DesignSystem.Colors.accent.opacity(0.1))
                    .foregroundStyle(DesignSystem.Colors.accent)
                    .cornerRadius(DesignSystem.Radius.sm)
            }
            .buttonStyle(.plain)
        }
    }
    
    @ViewBuilder
    private var credentialsGrid: some View {
        if viewModel.credentials.isEmpty {
            EmptyStateView(
                title: "No Credentials",
                description: "Add a password or key to automate your login.",
                systemImage: "key.slash"
            )
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 300))], spacing: DesignSystem.Spacing.medium) {
                ForEach(viewModel.credentials) { credential in
                    CredentialCard(credential: credential, vaultKey: vaultKey, isCopied: copiedId == credential.id) {
                        copyPassword(for: credential)
                    }
                    .contextMenu {
                        Button {
                            credentialToEdit = credential
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        
                        Button(role: .destructive) {
                            viewModel.deleteCredential(credential: credential)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
        }
    }

    
    func connect(protocol type: String) {
        Task {
            let cmd: String
            if type.lowercased().contains("sftp") {
                cmd = SFTPConnection.generateCommand(for: host, user: nil, key: vaultKey)
            } else {
                cmd = SSHConnection.generateCommand(for: host, user: nil, key: vaultKey)
            }
            
            // Find a password credential - prefer 'password' type
            var password: String? = nil
            var isInteractive = false
            if let cred = viewModel.credentials.first(where: { $0.type == "password" }) {
                password = viewModel.decrypt(credential: cred)
                isInteractive = cred.isInteractive
            }
            
            await TerminalLauncher.openInTerminal(command: cmd, password: password, isInteractive: isInteractive)
        }
    }

    func copyPassword(for credential: Credential) {
        if let secret = viewModel.decrypt(credential: credential) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(secret, forType: .string)
            copiedId = credential.id
            
            // Reset checkmark after 2 seconds
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                if copiedId == credential.id {
                    copiedId = nil
                }
            }
        }
    }
}

struct CredentialCard: View {
    let credential: Credential
    let vaultKey: SymmetricKey
    let isCopied: Bool
    let action: () -> Void
    @State private var isHovering = false
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(credential.decryptedUsername(using: vaultKey))
                    .font(DesignSystem.Typography.heading())
                    .foregroundStyle(DesignSystem.Colors.textPrimary)
                
                HStack(spacing: 6) {
                    Image(systemName: credential.type == "key" ? "key.fill" : "textformat.asterisk")
                        .font(.caption2)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    
                    Text(credential.type.capitalized)
                        .font(DesignSystem.Typography.label())
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
            }
            
            Spacer()
            
            Button(action: action) {
                Image(systemName: isCopied ? "checkmark" : "doc.on.doc")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(isCopied ? Color.green : DesignSystem.Colors.accent)
                    .frame(width: 32, height: 32)
                    .background(isCopied ? Color.green.opacity(0.1) : DesignSystem.Colors.accent.opacity(0.1))
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)
        }
        .padding(DesignSystem.Spacing.medium)
        .background(DesignSystem.Colors.surface)
        .cornerRadius(DesignSystem.Radius.md)
        .overlay(
            RoundedRectangle(cornerRadius: DesignSystem.Radius.md)
                .stroke(DesignSystem.Colors.border, lineWidth: 1)
        )
        .scaleEffect(isHovering ? 1.02 : 1.0)
        .shadow(color: isHovering ? Color.black.opacity(0.1) : Color.clear, radius: 4, x: 0, y: 2)
        .animation(.spring(response: 0.3, dampingFraction: 0.7), value: isHovering)
        .onHover { hover in
            isHovering = hover
        }
    }
}


