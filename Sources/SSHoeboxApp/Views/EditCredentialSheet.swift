import SwiftUI
import SSHoeboxCore
import CryptoKit

struct EditCredentialSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: CredentialsViewModel
    let credential: Credential
    let vaultKey: SymmetricKey

    @State private var username: String
    @State private var type: String
    @State private var secret: String
    @State private var agentKey: SSHAgentKeyReference?
    @State private var isInteractive: Bool

    private var isAgent: Bool { type == SSHAgentKeyReference.credentialType }

    /// What gets encrypted and stored: the typed secret, or for an agent key its reference.
    private var secretToSave: String? {
        if isAgent {
            return agentKey.flatMap { try? $0.encoded() }.flatMap { String(data: $0, encoding: .utf8) }
        }
        return secret.isEmpty ? nil : secret
    }

    init(viewModel: CredentialsViewModel, credential: Credential, vaultKey: SymmetricKey) {
        self.viewModel = viewModel
        self.credential = credential
        self.vaultKey = vaultKey

        // Decrypt and pre-populate fields
        _username = State(initialValue: credential.decryptedUsername(using: vaultKey))
        _type = State(initialValue: credential.type)

        // Decrypt secret. An agent credential's blob is its key reference, not a secret to show.
        if credential.type == SSHAgentKeyReference.credentialType {
            _agentKey = State(initialValue: viewModel.agentKey(for: credential))
            _secret = State(initialValue: "")
        } else {
            let decryptedSecret = viewModel.decrypt(credential: credential) ?? ""
            _secret = State(initialValue: decryptedSecret)
        }
        _isInteractive = State(initialValue: credential.isInteractive)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Username", text: $username)
                        .autocorrectionDisabled()

                    Picker("Type", selection: $type) {
                        Text("Password").tag("password")
                        Text("Private Key").tag("key")
                        Text("SSH Agent (Bitwarden)").tag(SSHAgentKeyReference.credentialType)
                    }
                }

                if isAgent {
                    AgentKeyPicker(reference: $agentKey)
                } else {
                    Section("Secret") {
                        if type == "password" {
                            SecureField("Password", text: $secret)
                        } else {
                            TextEditor(text: $secret)
                                .frame(minHeight: 100)
                                .font(.monospaced(.caption)())
                                .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.gray.opacity(0.4)))
                        }
                    }

                    Section {
                        Toggle("Interactive authentication (YubiKey, hardware tokens)", isOn: $isInteractive)
                            .help("Enable for YubiKey or other hardware token authentication that requires manual interaction")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Edit Credential")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if !username.isEmpty, let secretToSave {
                            viewModel.updateCredential(
                                id: credential.id,
                                username: username,
                                type: type,
                                secret: secretToSave,
                                isInteractive: isAgent ? false : isInteractive
                            )
                            dismiss()
                        }
                    }
                    .disabled(username.isEmpty || secretToSave == nil)
                }
            }
        }
        .frame(minWidth: 400, minHeight: 350)
    }
}
