import SwiftUI

struct AddCredentialSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: CredentialsViewModel
    
    @State private var username = ""
    @State private var type = "password"
    @State private var secret = ""
    @State private var isInteractive = false
    
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
                
                Section {
                    Toggle("Interactive authentication (YubiKey, hardware tokens)", isOn: $isInteractive)
                        .help("Enable for YubiKey or other hardware token authentication that requires manual interaction")
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
                        if !username.isEmpty, !secret.isEmpty {
                            viewModel.addCredential(username: username, type: type, secret: secret, isInteractive: isInteractive)
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
