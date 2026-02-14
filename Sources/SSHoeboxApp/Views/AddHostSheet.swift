import SwiftUI

struct AddHostSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: HostsViewModel
    
    @State private var name = ""
    @State private var hostname = ""
    @State private var port = "22"
    @State private var protocolType = "ssh"
    @State private var user = ""
    
    // New Credential Fields
    @State private var credentialType = "none" // none, password, key
    @State private var password = ""
    @State private var keyPath = ""
    @State private var isFileImporterPresented = false
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Information") {
                    TextField("Friendly Name (e.g. Prod Server)", text: $name)
                    TextField("Hostname / IP", text: $hostname)
                        .autocorrectionDisabled()
                    TextField("Port", text: $port)
                    TextField("Default User", text: $user)
                        .autocorrectionDisabled()
                }
                
                Section("Protocol") {
                    Picker("Protocol", selection: $protocolType) {
                        Text("SSH").tag("ssh")
                        Text("SFTP").tag("sftp")
                        Text("FTP").tag("ftp")
                    }
                    .pickerStyle(.segmented)
                }
                
                Section("Initial Credential (Optional)") {
                    Picker("Type", selection: $credentialType) {
                        Text("None").tag("none")
                        Text("Password").tag("password")
                        Text("Private Key").tag("key")
                    }
                    .pickerStyle(.segmented)
                    
                    if credentialType == "password" {
                        SecureField("Password", text: $password)
                    } else if credentialType == "key" {
                        HStack {
                            TextField("Path to Private Key", text: $keyPath)
                            Button {
                                isFileImporterPresented = true
                            } label: {
                                Image(systemName: "folder")
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("New Host")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if let portInt = Int(port), !name.isEmpty, !hostname.isEmpty {
                            viewModel.addHost(
                                name: name, 
                                hostname: hostname, 
                                port: portInt, 
                                protocolType: protocolType, 
                                user: user,
                                credentialType: credentialType,
                                credentialSecret: credentialType == "password" ? password : keyPath
                            )
                            dismiss()
                        }
                    }
                    .disabled(name.isEmpty || hostname.isEmpty)
                }
            }
            .fileImporter(isPresented: $isFileImporterPresented, allowedContentTypes: [.item]) { result in
                switch result {
                case .success(let url):
                    keyPath = url.path
                case .failure(let error):
                    print("Error selecting key: \(error.localizedDescription)")
                }
            }
        }
        .frame(minWidth: 400, minHeight: 500)
    }
}
