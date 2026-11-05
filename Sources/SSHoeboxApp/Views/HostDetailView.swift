import SwiftUI
import SSHoeboxCore
import CryptoKit

struct HostDetailView: View {
    @ObservedObject private var themeManager = ThemeManager.shared
    @EnvironmentObject private var sessionRegistry: TerminalSessionRegistry
    @EnvironmentObject private var navigator: AppNavigator
    @Environment(\.dismiss) var dismiss
    let host: SavedHost
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @StateObject private var viewModel: CredentialsViewModel
    @ObservedObject private var hostsViewModel: HostsViewModel
    @State private var showingAddCredential = false
    @State private var showingGenerateKey = false
    @State private var showingEditHost = false
    @State private var showingDeleteAlert = false
    @State private var credentialToEdit: Credential? = nil
    @State private var copiedId: String? = nil
    @State private var credentialForHistory: Credential? = nil
    @State private var keyToInstall: KeyToInstall? = nil
    @State private var publicKeyError: String? = nil
    @State private var selectedTab: HostTab = .credentials
    @StateObject private var sftpManager = SFTPSessionManager()

    enum HostTab {
        case credentials, terminal, files
    }

    struct KeyToInstall: Identifiable {
        let id = UUID()
        let line: String
        let name: String
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
        .sheet(isPresented: $showingGenerateKey) {
            GenerateKeySheet(viewModel: viewModel, vaultKey: vaultKey)
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
        .sheet(item: $keyToInstall) { key in
            InstallKeySheet(publicKeyLine: key.line, keyName: key.name, initialHostId: host.id,
                            dbManager: dbManager, vaultKey: vaultKey)
        }
        .alert("Public Key Unavailable", isPresented: Binding(get: { publicKeyError != nil },
                                                             set: { if !$0 { publicKeyError = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(publicKeyError ?? "")
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
        .onAppear { performPendingAction() }
        .onChange(of: navigator.pendingAction) { performPendingAction() }
        .onChange(of: selectedTab) { _, newTab in
            if newTab == .files && sftpManager.connectionState == .disconnected {
                Task { await connectSFTP() }
            }
            if newTab == .terminal {
                openTerminalIfNeeded()
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
                showingGenerateKey = true
            } label: {
                Label("Generate Key", systemImage: "key.badge.plus")
                    .font(DesignSystem.Typography.label())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(DesignSystem.Colors.surface)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .cornerRadius(DesignSystem.Radius.sm)
            }
            .buttonStyle(.plain)

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

                        if credential.type == "key" || credential.type == SSHAgentKeyReference.credentialType {
                            Divider()
                            Button {
                                showInstallKey(for: credential)
                            } label: {
                                Label("Install Public Key on Server…", systemImage: "key.horizontal")
                            }
                            Button {
                                if let line = publicKeyLine(for: credential) {
                                    ClipboardManager.shared.copy(line)
                                }
                            } label: {
                                Label("Copy Public Key", systemImage: "doc.on.doc")
                            }
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

    
    /// Runs what Quick Connect, a link or the host list asked for, once this host is showing.
    private func performPendingAction() {
        guard let action = navigator.takeAction(for: host.id) else { return }
        switch action {
        case .terminal: connect(protocol: "ssh")
        case .files: connect(protocol: "sftp")
        case .newTerminal:
            selectedTab = .terminal
            sessionRegistry.store(for: host, dbManager: dbManager, vaultKey: vaultKey).openNewSession()
        case .show: break
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
            // onChange doesn't fire if the Terminal tab was already showing
            openTerminalIfNeeded()
        }
    }

    /// Opens the first terminal session the first time the user asks for the terminal.
    private func openTerminalIfNeeded() {
        let store = sessionRegistry.store(for: host, dbManager: dbManager, vaultKey: vaultKey)
        if store.sessions.isEmpty {
            store.openNewSession()
        }
    }

    @MainActor
    private func connectSFTP() async {
        guard sftpManager.connectionState == .disconnected else { return }
        sftpManager.knownHostRepository = KnownHostRepository(dbManager: dbManager)
        do {
            let plan = try HostConnectionPlanner(dbManager: dbManager, vaultKey: vaultKey).plan(for: host)
            await sftpManager.connect(plan.target, via: plan.jumps, options: plan.options)
        } catch {
            sftpManager.errorMessage = error.localizedDescription
        }
    }

    /// The credential's OpenSSH public key line, or nil (with the reason shown) if it can't be read.
    private func publicKeyLine(for credential: Credential) -> String? {
        let comment = credential.decryptedUsername(using: vaultKey) + "@" + host.decryptedName(using: vaultKey)
        if let agentKey = viewModel.agentKey(for: credential) {
            return agentKey.publicKey
        }
        guard let pem = viewModel.decrypt(credential: credential) else {
            publicKeyError = "The stored key couldn't be decrypted."
            return nil
        }
        do {
            return try AuthorizedKeys.publicKeyLine(fromPEM: pem, comment: "sshoebox " + comment)
        } catch {
            publicKeyError = error.localizedDescription
            return nil
        }
    }

    private func showInstallKey(for credential: Credential) {
        guard let line = publicKeyLine(for: credential) else { return }
        let name = credential.type == SSHAgentKeyReference.credentialType ? "the agent key" : "this key"
        keyToInstall = KeyToInstall(line: line, name: name)
    }

    /// Copies the secret, or for an agent credential its public key (handy for authorized_keys).
    func copyPassword(for credential: Credential) {
        let copied = credential.type == SSHAgentKeyReference.credentialType
            ? viewModel.agentKey(for: credential)?.publicKey
            : viewModel.decrypt(credential: credential)
        guard let secret = copied else { return }
        ClipboardManager.shared.copy(secret)
        copiedId = credential.id
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if copiedId == credential.id { copiedId = nil }
        }
    }
}

struct CredentialCard: View {
    static func icon(for type: String) -> String {
        switch type {
        case "key": return "key.fill"
        case SSHAgentKeyReference.credentialType: return "person.badge.key.fill"
        default: return "textformat.asterisk"
        }
    }

    static func label(for type: String) -> String {
        type == SSHAgentKeyReference.credentialType ? "SSH Agent" : type.capitalized
    }

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
                    Image(systemName: Self.icon(for: credential.type))
                        .font(.caption2)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    
                    Text(Self.label(for: credential.type))
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


