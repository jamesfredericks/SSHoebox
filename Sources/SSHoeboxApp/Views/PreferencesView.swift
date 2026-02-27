import SwiftUI
import SSHoeboxCore

struct PreferencesView: View {
    @ObservedObject var viewModel: VaultViewModel
    @ObservedObject var themeManager = ThemeManager.shared
    @State private var autoLockTimeout: Int = 15
    @State private var isBiometricEnabled: Bool = false
    @State private var showBiometricVaultLockedAlert: Bool = false
    
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
            } header: {
                Text("Security")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            } footer: {
                Text("Automatically lock the vault after a period of inactivity.")
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
            // Read biometric state fresh from the source of truth
            isBiometricEnabled = BiometricAuthManager.isBiometricEnrolled
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
}
