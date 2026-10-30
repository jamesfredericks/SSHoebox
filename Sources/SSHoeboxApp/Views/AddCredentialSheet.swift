import SwiftUI
import SSHoeboxCore

struct AddCredentialSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: CredentialsViewModel

    @State private var username = ""
    @State private var type = "password"
    @State private var secret = ""
    @State private var agentKey: SSHAgentKeyReference?
    @State private var isInteractive = false

    private var isAgent: Bool { type == SSHAgentKeyReference.credentialType }

    /// What gets encrypted and stored: the typed secret, or for an agent key its reference.
    private var secretToSave: String? {
        if isAgent {
            return agentKey.flatMap { try? $0.encoded() }.flatMap { String(data: $0, encoding: .utf8) }
        }
        return secret.isEmpty ? nil : secret
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
            .navigationTitle("New Credential")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if !username.isEmpty, let secretToSave {
                            viewModel.addCredential(username: username, type: type, secret: secretToSave,
                                                    isInteractive: isAgent ? false : isInteractive)
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
