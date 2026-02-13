import SwiftUI
import SSHoeboxCore

struct VaultUnlockView: View {
    @ObservedObject var viewModel: VaultViewModel
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var showingResetAlert = false
    
    var body: some View {
        ZStack {
            // GLOBAL BACKGROUND: Fills the entire window edge-to-edge
            DesignSystem.Colors.background
                .ignoresSafeArea()
            
            VStack(spacing: 30) {
                // Centered content container
                VStack(spacing: 25) {
                    // Restored logo size and removed processing effects
                    if let logoUrl = Bundle.module.url(forResource: "logo", withExtension: "png"),
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
                
                Button(viewModel.isNewUser ? "Create Vault" : "Unlock") {
                    submit()
                }
                .buttonStyle(.borderedProminent)
                .tint(DesignSystem.Colors.accent)
                .keyboardShortcut(.defaultAction)
                
                if viewModel.isNewUser {
                    Text("This password encrypts your entire vault. Don't lose it!")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
                
                VStack(spacing: 15) {
                    Divider()
                        .background(DesignSystem.Colors.border)
                    
                    Button("Reset App (Delete All Data)") {
                        showingResetAlert = true
                    }
                    .foregroundStyle(.red)
                    .buttonStyle(.plain)
                    .font(.caption)
                }
                .frame(maxWidth: 400)
            }
            .padding(40)
        }
        .frame(minWidth: 600, minHeight: 600)
        .alert("Reset Application?", isPresented: $showingResetAlert) {
            Button("Cancel", role: .cancel) { }
            Button("Reset", role: .destructive) {
                viewModel.resetApp()
            }
        } message: {
            Text("This will delete all your hosts, credentials, and settings. This action cannot be undone.")
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
