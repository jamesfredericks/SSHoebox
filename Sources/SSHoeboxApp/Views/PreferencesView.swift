import SwiftUI
import SSHoeboxCore

struct PreferencesView: View {
    @ObservedObject var viewModel: VaultViewModel
    @ObservedObject var themeManager = ThemeManager.shared
    @State private var autoLockTimeout: Int = 15
    @State private var clipboardClearTimeout: Int = 30
    @State private var isBiometricEnabled: Bool = false
    @State private var showBiometricVaultLockedAlert: Bool = false
    @State private var knownHosts: [KnownHost] = []
    @State private var knownHostToDelete: KnownHost? = nil
    @State private var showDeleteKnownHostAlert: Bool = false
    
    var body: some View {
        Form {
            Section {
                Picker("Auto-lock after", selection: $autoLockTimeout) {
                    Text("5 minutes").tag(5)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("15 minutes").tag(15)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("30 minutes").tag(30)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("1 hour").tag(60)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("Never").tag(0)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                }
                .onChange(of: autoLockTimeout) { newValue in
                    UserDefaults.standard.set(newValue, forKey: "autoLockTimeout")
                    UserDefaults.standard.set(true, forKey: "hasSetAutoLockTimeout")
                }

                Picker("Clear clipboard after", selection: $clipboardClearTimeout) {
                    Text("15 seconds").tag(15)
                    Text("30 seconds").tag(30)
                    Text("1 minute").tag(60)
                    Text("2 minutes").tag(120)
                    Text("Never").tag(0)
                }
                .onChange(of: clipboardClearTimeout) { newValue in
                    UserDefaults.standard.set(newValue, forKey: "clipboardClearTimeout")
                    ClipboardManager.shared.clipboardClearTimeout = newValue
                }
            } header: {
                Text("Security")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            } footer: {
                Text("Automatically lock the vault after a period of inactivity. Copied secrets are cleared from the clipboard after the configured delay.")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            // Vault Location Section
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Current Location")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    
                    HStack {
                        Text(viewModel.vaultDirectoryURL.path)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                        
                        Spacer()
                        
                        Button {
                            NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: viewModel.vaultDirectoryURL.path)
                        } label: {
                            Image(systemName: "folder")
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                        .help("Show in Finder")
                    }
                    .padding(8)
                    .background(DesignSystem.Colors.surface)
                    .cornerRadius(6)
                    
                    HStack(spacing: 12) {
                        Button("Move Vault...") {
                            let panel = NSOpenPanel()
                            panel.canChooseFiles = false
                            panel.canChooseDirectories = true
                            panel.canCreateDirectories = true
                            panel.prompt = "Move Vault Here"
                            panel.message = "Select a new folder to store your vault database and encryption metadata."
                            
                            if panel.runModal() == .OK, let url = panel.url {
                                do {
                                    try viewModel.moveVault(to: url)
                                } catch {
                                    viewModel.errorMessage = "Failed to move vault: \(error.localizedDescription)"
                                }
                            }
                        }
                        .buttonStyle(.bordered)
                        
                        Button("Open Existing Vault...") {
                            let panel = NSOpenPanel()
                            panel.canChooseFiles = false
                            panel.canChooseDirectories = true
                            panel.prompt = "Open Vault"
                            panel.message = "Select an existing folder that contains a SSHoebox vault.db and vault_metadata.json."
                            
                            if panel.runModal() == .OK, let url = panel.url {
                                viewModel.openExistingVault(at: url)
                            }
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding(.top, 4)
                }
            } header: {
                Text("Vault Storage")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            } footer: {
                Text("Store your vault in a cloud folder (like iCloud Drive or Dropbox) to sync across your Macs.")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            // Biometric unlock section — only shown if available
            if BiometricAuthManager.isBiometricAvailable() {
                Section {
                    Toggle(isOn: $isBiometricEnabled) {
                        Label("Unlock with \(BiometricAuthManager.biometricTypeName())",
                              systemImage: BiometricAuthManager.biometricSymbolName())
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                    }
                    .onChange(of: isBiometricEnabled) { enabled in
                        if enabled {
                            // Re-enroll using the current vault key (requires vault to be unlocked)
                            if viewModel.vaultKey != nil {
                                viewModel.enrollBiometrics()
                                // Sync toggle back if enrollment failed
                                isBiometricEnabled = BiometricAuthManager.isBiometricEnrolled
                            } else {
                                // Vault is locked — can't enroll without the key
                                isBiometricEnabled = false
                                showBiometricVaultLockedAlert = true
                            }
                        } else {
                            BiometricAuthManager.revokeBiometric()
                        }
                    }
                } header: {
                    Text("Biometric Unlock")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                } footer: {
                    Text(isBiometricEnabled
                         ? "\(BiometricAuthManager.biometricTypeName()) is enabled. Disable to require your master password each time."
                         : "Enable \(BiometricAuthManager.biometricTypeName()) to unlock your vault without typing your master password.")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
            }
            
            // SSH Agent Section
            Section {
                Toggle("Enable SSH Agent", isOn: $viewModel.isAgentEnabled)
                
                if viewModel.isAgentEnabled {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Socket Path")
                            .font(.caption)
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                        
                        HStack {
                            Text(viewModel.agentSocketPath ?? "Unavailable")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(DesignSystem.Colors.textPrimary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .textSelection(.enabled)
                            
                            Spacer()
                            
                            Button {
                                if let path = viewModel.agentSocketPath {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(path, forType: .string)
                                }
                            } label: {
                                Image(systemName: "doc.on.doc")
                                    .font(.caption)
                            }
                            .buttonStyle(.plain)
                        }
                        .padding(8)
                        .background(DesignSystem.Colors.surface)
                        .cornerRadius(6)
                        
                        Text("Use this socket path for SSH_AUTH_SOCK to access keys in other apps.")
                            .font(.caption)
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                    }
                    .padding(.vertical, 4)
                }
            } header: {
                Text("SSH Agent")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            // Known Hosts Section
            Section {
                if knownHosts.isEmpty {
                    HStack {
                        Spacer()
                        VStack(spacing: DesignSystem.Spacing.standard) {
                            Image(systemName: "checkmark.shield")
                                .font(.system(size: 28))
                                .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.5))
                            Text("No trusted host keys yet.")
                                .font(DesignSystem.Typography.body())
                                .foregroundStyle(DesignSystem.Colors.textSecondary)
                        }
                        .padding(.vertical, DesignSystem.Spacing.medium)
                        Spacer()
                    }
                } else {
                    ForEach(knownHosts) { host in
                        KnownHostRow(knownHost: host) {
                            knownHostToDelete = host
                            showDeleteKnownHostAlert = true
                        }
                    }
                }
            } header: {
                Text("Known Hosts")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            } footer: {
                Text("Trusted SSH host keys, stored on first connection. Remove an entry if a server's key has legitimately changed (e.g. after a reinstall), then reconnect to re-trust it.")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }

            Section {
                Picker(selection: Binding(
                    get: { themeManager.currentTheme.id },
                    set: { themeManager.setTheme(id: $0) }
                )) {
                    ForEach(AppTheme.allThemes) { theme in
                        Text(theme.name)
                            .tag(theme.id)
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                    }
                } label: {
                    Text("Theme")
                        .foregroundStyle(DesignSystem.Colors.textPrimary)
                }
                .pickerStyle(.inline)
                .labelsHidden()

                HStack {
                    Text("Terminal Font Size")
                        .foregroundStyle(DesignSystem.Colors.textPrimary)
                    Spacer()
                    Stepper(value: $themeManager.terminalFontSize, in: 8...32, step: 1) {
                        Text("\(Int(themeManager.terminalFontSize)) pt")
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                            .monospacedDigit()
                    }
                }
            } header: {
                Text("Appearance")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            Section {
                HStack {
                    Text("Version")
                        .foregroundStyle(DesignSystem.Colors.textPrimary)
                    Spacer()
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "2.2.1")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
            } header: {
                Text("About")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(DesignSystem.Colors.background)
        .preferredColorScheme(themeManager.currentTheme.colorScheme)
        .tint(DesignSystem.Colors.accent)
        .navigationTitle("Preferences")
        .onAppear {
            // Load saved preferences
            let saved = UserDefaults.standard.integer(forKey: "autoLockTimeout")
            if saved == 0 && !UserDefaults.standard.bool(forKey: "hasSetAutoLockTimeout") {
                autoLockTimeout = 15 // Default
            } else {
                autoLockTimeout = saved
            }
            let savedClipboard = UserDefaults.standard.integer(forKey: "clipboardClearTimeout")
            clipboardClearTimeout = savedClipboard == 0 ? 30 : savedClipboard
            // Read biometric state fresh from the source of truth
            isBiometricEnabled = BiometricAuthManager.isBiometricEnrolled
            loadKnownHosts()
        }
        .alert("Remove Trusted Key?", isPresented: $showDeleteKnownHostAlert, presenting: knownHostToDelete) { host in
            Button("Remove", role: .destructive) {
                deleteKnownHost(host)
            }
            Button("Cancel", role: .cancel) { }
        } message: { host in
            Text("The trusted key for \(host.hostname):\(host.port) will be removed. You will be asked to re-trust the server's key on your next connection.")
        }
        .alert("Vault Locked", isPresented: $showBiometricVaultLockedAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Unlock your vault with your master password first, then enable \(BiometricAuthManager.biometricTypeName()) from Preferences.")
        }
        .alert("Error", isPresented: Binding(
            get: { viewModel.errorMessage != nil },
            set: { if !$0 { viewModel.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
    }

    private func loadKnownHosts() {
        guard let db = viewModel.dbManager else { return }
        knownHosts = (try? KnownHostRepository(dbManager: db).getAll()) ?? []
    }

    private func deleteKnownHost(_ host: KnownHost) {
        guard let db = viewModel.dbManager else { return }
        try? KnownHostRepository(dbManager: db).delete(host)
        knownHosts.removeAll { $0.id == host.id }
    }
}

// MARK: - Known Host Row

struct KnownHostRow: View {
    let knownHost: KnownHost
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text("\(knownHost.hostname):\(knownHost.port)")
                    .font(DesignSystem.Typography.body())
                    .foregroundStyle(DesignSystem.Colors.textPrimary)

                Text(knownHost.keyType)
                    .font(.system(.caption2, design: .monospaced))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(DesignSystem.Colors.accent.opacity(0.15))
                    .foregroundStyle(DesignSystem.Colors.accent)
                    .cornerRadius(4)

                Spacer()

                Button(role: .destructive, action: onDelete) {
                    Image(systemName: "trash")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
                .buttonStyle(.plain)
                .help("Remove trusted key")
            }

            Text(knownHost.keyFingerprint)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            Text("Trusted since \(knownHost.firstSeenAt.formatted(date: .abbreviated, time: .omitted))")
                .font(.caption2)
                .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.7))
        }
        .padding(.vertical, 4)
    }
}
