import SwiftUI
import SSHoeboxCore

struct VaultUnlockView: View {
    @ObservedObject var viewModel: VaultViewModel
    @State private var password = ""
    @State private var confirmPassword = ""
    
    var body: some View {
        ZStack {
            // GLOBAL BACKGROUND: Fills the entire window edge-to-edge
            DesignSystem.Colors.background
                .ignoresSafeArea()
            
            VStack(spacing: 30) {
                // Centered content container
                VStack(spacing: 25) {
                    if let logoUrl = Bundle.main.url(forResource: "logo", withExtension: "png"),
                       let nsImage = NSImage(contentsOf: logoUrl) {
                        Image(nsImage: nsImage)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 140, height: 140)
                    } else {
                        Image(systemName: "lock.shield")
                            .font(.system(size: 80))
                            .foregroundStyle(DesignSystem.Colors.accent)
                    }
                    
                    Text(viewModel.isNewUser ? "Create Your Vault" : "Unlock SSHoebox")
                        .font(.title)
                        .fontWeight(.bold)
                        .foregroundStyle(DesignSystem.Colors.accent)
                }
                
                VStack(alignment: .leading, spacing: 10) {
                    SecureField("Master Password", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { submit() }
                    
                    if viewModel.isNewUser {
                        SecureField("Confirm Password", text: $confirmPassword)
                            .textFieldStyle(.roundedBorder)
                            .onSubmit { submit() }
                    }
                }
                .frame(maxWidth: 300)
                
                if let error = viewModel.errorMessage {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.caption)
                }
                
                VStack(spacing: 12) {
                    Button(viewModel.isNewUser ? "Create Vault" : "Unlock") {
                        submit()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(DesignSystem.Colors.accent)
                    .keyboardShortcut(.defaultAction)
                    
                    // Biometric unlock button — only shown when enrolled and not creating vault
                    if !viewModel.isNewUser && viewModel.isBiometricEnrolled {
                        Button {
                            viewModel.unlockWithBiometrics()
                        } label: {
                            Label("Unlock with \(viewModel.biometricTypeName)", systemImage: viewModel.biometricSymbolName)
                        }
                        .buttonStyle(.bordered)
                        .tint(DesignSystem.Colors.accent)
                    }
                }
                
                if viewModel.isNewUser {
                    Text("This password encrypts your entire vault. Don't lose it!")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
            }
            .padding(40)
        }
        .frame(minWidth: 600, minHeight: 600)
        // Biometric setup prompt shown after first password unlock
        .sheet(isPresented: $viewModel.showBiometricSetupPrompt) {
            BiometricSetupSheet(viewModel: viewModel)
        }
        // Auto-trigger biometric unlock on launch if enrolled
        .onAppear {
            if !viewModel.isNewUser && viewModel.isBiometricEnrolled {
                viewModel.unlockWithBiometrics()
            }
        }
    }
    
    func submit() {
        if viewModel.isNewUser {
            guard password == confirmPassword else {
                viewModel.errorMessage = "Passwords do not match."
                return
            }
            guard !password.isEmpty else { return }
            viewModel.createVault(password: password)
        } else {
            viewModel.unlock(password: password)
        }
    }
}

// MARK: - Biometric Setup Sheet

struct BiometricSetupSheet: View {
    @ObservedObject var viewModel: VaultViewModel
    
    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: viewModel.biometricSymbolName)
                .font(.system(size: 56))
                .foregroundStyle(DesignSystem.Colors.accent)
            
            Text("Enable \(viewModel.biometricTypeName)?")
                .font(.title2)
                .fontWeight(.bold)
                .foregroundStyle(DesignSystem.Colors.textPrimary)
            
            Text("Use \(viewModel.biometricTypeName) to unlock SSHoebox instead of typing your master password each time.")
                .font(.body)
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 320)
            
            HStack(spacing: 16) {
                Button("Not Now") {
                    viewModel.showBiometricSetupPrompt = false
                }
                .buttonStyle(.bordered)
                
                Button("Enable \(viewModel.biometricTypeName)") {
                    viewModel.enrollBiometrics()
                }
                .buttonStyle(.borderedProminent)
                .tint(DesignSystem.Colors.accent)
            }
        }
        .padding(40)
        .frame(minWidth: 420, minHeight: 300)
        .background(DesignSystem.Colors.background)
    }
}
