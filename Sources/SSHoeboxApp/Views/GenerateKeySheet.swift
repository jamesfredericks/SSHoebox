import SwiftUI
import SSHoeboxCore
import CryptoKit

/// Sheet for generating a new Ed25519 SSH key pair and saving it as a credential.
struct GenerateKeySheet: View {
    @ObservedObject var viewModel: CredentialsViewModel
    let vaultKey: SymmetricKey
    @Environment(\.dismiss) private var dismiss

    @State private var comment: String = ""
    @State private var generatedPair: SSHKeyGenerator.GeneratedKeyPair? = nil
    @State private var errorMessage: String? = nil
    @State private var copiedPublic = false
    @State private var saving = false

    var body: some View {
        VStack(spacing: DesignSystem.Spacing.large) {
            // Title
            HStack {
                Image(systemName: "key.fill")
                    .font(.system(size: 20))
                    .foregroundStyle(DesignSystem.Colors.accent)
                Text("Generate SSH Key")
                    .font(DesignSystem.Typography.heading())
                Spacer()
            }

            // Comment field
            VStack(alignment: .leading, spacing: 6) {
                Text("Comment (optional)")
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                TextField("e.g. james@macbook", text: $comment)
                    .textFieldStyle(.roundedBorder)
            }

            // Generate button
            Button("Generate Ed25519 Key Pair") {
                generate()
            }
            .buttonStyle(.borderedProminent)
            .tint(DesignSystem.Colors.accent)

            if let error = errorMessage {
                Text(error)
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(.red)
            }

            // Result
            if let pair = generatedPair {
                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    Text("Public Key")
                        .font(DesignSystem.Typography.label())
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    HStack(alignment: .top, spacing: 8) {
                        Text(pair.publicKeyOpenSSH)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                            .lineLimit(3)
                            .textSelection(.enabled)
                        Spacer(minLength: 0)
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(pair.publicKeyOpenSSH, forType: .string)
                            copiedPublic = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copiedPublic = false }
                        } label: {
                            Image(systemName: copiedPublic ? "checkmark" : "doc.on.doc")
                                .foregroundStyle(copiedPublic ? .green : DesignSystem.Colors.accent)
                        }
                        .buttonStyle(.plain)
                        .help("Copy public key")
                    }
                    .padding(10)
                    .background(DesignSystem.Colors.surface)
                    .cornerRadius(8)

                    Text("Add the public key to your server's ~/.ssh/authorized_keys. The private key will be saved to this host's credentials.")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                // Actions
                HStack {
                    Button("Cancel") { dismiss() }
                        .buttonStyle(.plain)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    Spacer()
                    Button("Save Private Key") {
                        saveKey(pair: pair)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(saving)
                }
            } else {
                Spacer()
                HStack {
                    Button("Cancel") { dismiss() }
                        .buttonStyle(.plain)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                    Spacer()
                }
            }
        }
        .padding(DesignSystem.Spacing.large)
        .frame(width: 460)
        .background(DesignSystem.Colors.background)
    }

    private func generate() {
        errorMessage = nil
        do {
            generatedPair = try SSHKeyGenerator.generateEd25519(comment: comment)
        } catch {
            errorMessage = "Key generation failed: \(error.localizedDescription)"
        }
    }

    private func saveKey(pair: SSHKeyGenerator.GeneratedKeyPair) {
        saving = true
        let username = comment.isEmpty ? "generated-key" : comment
        viewModel.addCredential(username: username, type: "key", secret: pair.privateKeyPEM)
        if let err = viewModel.errorMessage {
            errorMessage = err
            saving = false
        } else {
            dismiss()
        }
    }
}
