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
    
    init(viewModel: CredentialsViewModel, credential: Credential, vaultKey: SymmetricKey) {
        self.viewModel = viewModel
        self.credential = credential
        self.vaultKey = vaultKey
        
        // Decrypt and pre-populate fields
        _username = State(initialValue: credential.decryptedUsername(using: vaultKey))
        _type = State(initialValue: credential.type)
        
        // Decrypt secret
        let decryptedSecret = viewModel.decrypt(credential: credential) ?? ""
        _secret = State(initialValue: decryptedSecret)
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
                    }
                }
                
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
            }
            .formStyle(.grouped)
            .navigationTitle("Edit Credential")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if !username.isEmpty, !secret.isEmpty {
                            viewModel.updateCredential(
                                id: credential.id,
                                username: username,
                                type: type,
                                secret: secret
                            )
                            dismiss()
                        }
                    }
                    .disabled(username.isEmpty || secret.isEmpty)
                }
            }
        }
        .frame(minWidth: 400, minHeight: 350)
    }
}
