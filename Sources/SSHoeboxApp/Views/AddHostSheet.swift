import SwiftUI

struct AddHostSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: HostsViewModel
    
    @State private var name = ""
    @State private var hostname = ""
    @State private var port = "22"
    @State private var protocolType = "ssh"
    @State private var user = ""
    @State private var selectedGroupId: String? = nil
    
    // New Credential Fields
    @State private var credentialType = "none" // none, password, key
    @State private var password = ""
    @State private var keyText = ""
    @State private var keyError: String?
    @State private var isFileImporterPresented = false

    /// The stored secret is the key itself, so only accept something that looks like one.
    private var keyLooksValid: Bool {
        keyText.contains("-----BEGIN") && keyText.contains("PRIVATE KEY-----")
    }
    
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
                
                if !viewModel.groups.isEmpty {
                    Section("Group") {
                        Picker("Group", selection: $selectedGroupId) {
                            Text("None").tag(String?.none)
                            ForEach(viewModel.groups) { group in
                                Text(group.name).tag(Optional(group.id))
                            }
                        }
                    }
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
                        TextEditor(text: $keyText)
                            .font(.system(.caption, design: .monospaced))
                            .frame(minHeight: 100)
                            .autocorrectionDisabled()
                            .onChange(of: keyText) { keyError = nil }
                        Button("Load from File…") {
                            isFileImporterPresented = true
                        }
                        if let keyError {
                            Text(keyError)
                                .font(.caption)
                                .foregroundStyle(.red)
                        } else if !keyText.isEmpty && !keyLooksValid {
                            Text("This doesn't look like a private key. Paste the contents of the private key file (not the .pub file).")
                                .font(.caption)
                                .foregroundStyle(.red)
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
                                groupId: selectedGroupId,
                                credentialType: credentialType,
                                credentialSecret: credentialType == "password" ? password : keyText
                            )
                            dismiss()
                        }
                    }
                    .disabled(name.isEmpty || hostname.isEmpty || (credentialType == "key" && !keyText.isEmpty && !keyLooksValid))
                }
            }
            .fileImporter(isPresented: $isFileImporterPresented, allowedContentTypes: [.item]) { result in
                switch result {
                case .success(let url):
                    loadKey(from: url)
                case .failure(let error):
                    keyError = "Could not open the file: \(error.localizedDescription)"
                }
            }
        }
        .frame(minWidth: 400, minHeight: 500)
    }

    /// Reads the private key's contents into the editor; the vault stores the key, not its path.
    private func loadKey(from url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= 64 * 1024 else {
                keyError = "That file is too large to be a private key."
                return
            }
            keyText = try String(contentsOf: url, encoding: .utf8)
            keyError = nil
        } catch {
            keyError = "Could not read the key file: \(error.localizedDescription)"
        }
    }
}
