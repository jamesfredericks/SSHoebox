import SwiftUI
import SSHoeboxCore
import CryptoKit

struct EditHostSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: HostsViewModel
    let host: SavedHost
    let vaultKey: SymmetricKey
    
    @State private var name: String
    @State private var hostname: String
    @State private var port: String
    @State private var protocolType: String
    @State private var user: String
    @State private var selectedGroupId: String?
    @State private var options: HostOptions
    
    init(viewModel: HostsViewModel, host: SavedHost, vaultKey: SymmetricKey) {
        self.viewModel = viewModel
        self.host = host
        self.vaultKey = vaultKey
        
        _name = State(initialValue: host.decryptedName(using: vaultKey))
        _hostname = State(initialValue: host.decryptedHostname(using: vaultKey))
        _port = State(initialValue: String(host.port))
        _protocolType = State(initialValue: host.protocolType)
        _user = State(initialValue: host.decryptedUser(using: vaultKey))
        _selectedGroupId = State(initialValue: host.groupId)
        _options = State(initialValue: host.decryptedOptions(using: vaultKey))
    }

    private var jumpCandidates: [(id: String, name: String)] {
        viewModel.hosts.filter { $0.id != host.id }
            .map { ($0.id, viewModel.name(of: $0)) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
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

                HostOptionsSections(options: $options, jumpCandidates: jumpCandidates)
            }
            .formStyle(.grouped)
            .navigationTitle("Edit Host")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if let portInt = Int(port), !name.isEmpty, !hostname.isEmpty {
                            viewModel.updateHost(
                                id: host.id,
                                name: name,
                                hostname: hostname,
                                port: portInt,
                                protocolType: protocolType,
                                user: user,
                                groupId: selectedGroupId,
                                options: options
                            )
                            dismiss()
                        }
                    }
                    .disabled(name.isEmpty || hostname.isEmpty || !HostOptionsSections.forwardsAreValid(options))
                }
            }
        }
        .frame(minWidth: 520, minHeight: 560)
    }
}
