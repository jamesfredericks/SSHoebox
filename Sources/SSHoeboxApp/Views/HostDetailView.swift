import SwiftUI
import SSHoeboxCore
import CryptoKit

struct HostDetailView: View {
    @ObservedObject private var themeManager = ThemeManager.shared
    @EnvironmentObject private var sessionRegistry: TerminalSessionRegistry
    @Environment(\.dismiss) var dismiss
    let host: SavedHost
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @StateObject private var viewModel: CredentialsViewModel
    @ObservedObject private var hostsViewModel: HostsViewModel
    @State private var showingAddCredential = false
    @State private var showingEditHost = false
    @State private var showingDeleteAlert = false
    @State private var credentialToEdit: Credential? = nil
    @State private var copiedId: String? = nil
    @State private var credentialForHistory: Credential? = nil
    @State private var selectedTab: HostTab = .credentials
    @StateObject private var sftpManager = SFTPSessionManager()

    enum HostTab {
        case credentials, terminal, files
    }
    
    init(host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey, hostsViewModel: HostsViewModel) {
        self.host = host
        self.dbManager = dbManager
        self.vaultKey = vaultKey
        _viewModel = StateObject(wrappedValue: CredentialsViewModel(dbManager: dbManager, vaultKey: vaultKey, hostId: host.id))
        _hostsViewModel = ObservedObject(wrappedValue: hostsViewModel)
    }
    
    var body: some View {
        let sessionStore = sessionRegistry.store(for: host, dbManager: dbManager, vaultKey: vaultKey)
        VStack(spacing: 0) {
            heroHeader
            
            // Always render both tab contents; hide with opacity so views are never destroyed.
            // This keeps SSH sessions alive when switching to the Credentials tab and back.
            ZStack {
                contentList
                    .opacity(selectedTab == .credentials ? 1 : 0)
                    .allowsHitTesting(selectedTab == .credentials)
                
                TerminalTabView(store: sessionStore)
                    .opacity(selectedTab == .terminal ? 1 : 0)
                    .allowsHitTesting(selectedTab == .terminal)

                SFTPBrowserView(sftp: sftpManager)
                    .opacity(selectedTab == .files ? 1 : 0)
                    .allowsHitTesting(selectedTab == .files)
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
        .sheet(item: $credentialForHistory) { credential in
            PasswordHistorySheet(credential: credential, dbManager: dbManager, vaultKey: vaultKey)
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
        .onChange(of: selectedTab) { _, newTab in
            if newTab == .files && sftpManager.connectionState == .disconnected {
                Task { await connectSFTP() }
            }
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
                Label("Files", systemImage: "folder").tag(HostDetailView.HostTab.files)
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

                        Button {
                            credentialForHistory = credential
                        } label: {
                            Label("View History", systemImage: "clock.arrow.circlepath")
                        }

                        Divider()

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
        if type == "sftp" {
            selectedTab = .files
            if sftpManager.connectionState == .disconnected {
                Task { await connectSFTP() }
            }
        } else {
            selectedTab = .terminal
        }
    }

    @MainActor
    private func connectSFTP() async {
        guard sftpManager.connectionState == .disconnected else { return }

        sftpManager.knownHostRepository = KnownHostRepository(dbManager: dbManager)

        let hostname   = host.decryptedHostname(using: vaultKey)
        let defaultUser = host.decryptedUser(using: vaultKey)

        viewModel.fetchCredentials()

        // Prefer password credential; fall back to key
        if let pwCred = viewModel.credentials.first(where: { $0.type == "password" }) {
            let user = {
                let u = pwCred.decryptedUsername(using: vaultKey)
                return u.isEmpty ? defaultUser : u
            }()
            if let secret = viewModel.decrypt(credential: pwCred) {
                await sftpManager.connect(host: hostname, port: host.port, username: user, password: secret)
                return
            }
        }

        if let keyCred = viewModel.credentials.first(where: { $0.type == "key" }) {
            let user = {
                let u = keyCred.decryptedUsername(using: vaultKey)
                return u.isEmpty ? defaultUser : u
            }()
            if let pem = viewModel.decrypt(credential: keyCred) {
                await sftpManager.connect(host: hostname, port: host.port, username: user, pemKey: pem)
                return
            }
        }
    }

    func copyPassword(for credential: Credential) {
        guard let secret = viewModel.decrypt(credential: credential) else { return }
        ClipboardManager.shared.copy(secret)
        copiedId = credential.id
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if copiedId == credential.id { copiedId = nil }
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


