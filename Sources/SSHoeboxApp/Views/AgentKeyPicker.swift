import SwiftUI
import SSHoeboxCore

/// Chooses a key held by an external SSH agent (Bitwarden by default) for an `agent`
/// credential. Only the agent's socket path and the key's public half are stored.
struct AgentKeyPicker: View {
    @Binding var reference: SSHAgentKeyReference?

    @State private var socketPath: String
    @State private var identities: [SSHAgentIdentity] = []
    @State private var selectedKey: Data?
    @State private var isLoading = false
    @State private var loadError: String?

    private let knownAgents = SSHAgentKeyReference.knownAgents
    /// The key saved before this edit, kept selectable while its agent doesn't offer it
    /// (e.g. Bitwarden is locked).
    private let savedReference: SSHAgentKeyReference?

    init(reference: Binding<SSHAgentKeyReference?>) {
        _reference = reference
        savedReference = reference.wrappedValue
        let defaultAgent = knownAgents.first(where: \.isRunning) ?? knownAgents[0]
        _socketPath = State(initialValue: reference.wrappedValue?.socketPath ?? defaultAgent.socketPath)
        _selectedKey = State(initialValue: reference.wrappedValue?.keyBlob)
    }

    /// The agent's keys, plus the saved key if this agent didn't list it.
    private var options: [SSHAgentIdentity] {
        guard let saved = savedReference, saved.socketPath == socketPath, let blob = saved.keyBlob,
              !identities.contains(where: { $0.keyBlob == blob }) else { return identities }
        return identities + [SSHAgentIdentity(keyBlob: blob, comment: saved.comment)]
    }

    var body: some View {
        Section {
            Picker("Agent", selection: $socketPath) {
                ForEach(knownAgents) { agent in
                    Text(agent.isRunning ? agent.name : "\(agent.name) (not running)").tag(agent.socketPath)
                }
                if !knownAgents.contains(where: { $0.socketPath == socketPath }) {
                    Text("Custom").tag(socketPath)
                }
            }

            TextField("Socket path", text: $socketPath)
                .font(.monospaced(.caption)())
                .autocorrectionDisabled()

            if isLoading {
                ProgressView().controlSize(.small)
            } else if let loadError {
                Text(loadError)
                    .font(.caption)
                    .foregroundStyle(.red)
            } else if options.isEmpty {
                Text("The agent offers no keys. Unlock your password manager, then reload.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Picker("Key", selection: $selectedKey) {
                    Text("Choose a key").tag(Data?.none)
                    ForEach(options) { identity in
                        Text(label(for: identity)).tag(Data?.some(identity.keyBlob))
                    }
                }
            }

            if let reference, let algorithm = reference.algorithm,
               !AgentBackedKey.supportedAlgorithms.contains(algorithm) {
                Text(SSHAgentClientError.unsupportedKeyType(algorithm).localizedDescription)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            Button("Reload Keys") { Task { await load() } }
                .disabled(isLoading)
        } header: {
            Text("SSH Agent")
        } footer: {
            Text("The private key stays in your password manager, which may ask you to approve each login.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .task(id: socketPath) { await load() }
        .onChange(of: selectedKey) { updateReference() }
    }

    private func label(for identity: SSHAgentIdentity) -> String {
        let name = identity.comment.isEmpty ? identity.algorithm : identity.comment
        let offered = identities.contains(identity) ? "" : " (not offered by agent)"
        return "\(name)  \(identity.fingerprint.prefix(20))…\(offered)"
    }

    private func load() async {
        let path = socketPath
        isLoading = true
        loadError = nil
        // The client blocks on the socket, so keep it off the main thread.
        let result = await Task.detached { Result { try SSHAgentClient(socketPath: path).identities() } }.value
        guard path == socketPath else { return } // the path changed while loading
        isLoading = false

        switch result {
        case .success(let loaded):
            identities = loaded
        case .failure(let error):
            identities = []
            loadError = error.localizedDescription
        }

        if let selected = selectedKey, !options.contains(where: { $0.keyBlob == selected }) {
            selectedKey = nil
        }
        // One usable key: pick it, so the common case is a single click.
        let usable = identities.filter { AgentBackedKey.supportedAlgorithms.contains($0.algorithm) }
        if selectedKey == nil, usable.count == 1 {
            selectedKey = usable[0].keyBlob
        }
        updateReference()
    }

    private func updateReference() {
        guard let selectedKey, let identity = options.first(where: { $0.keyBlob == selectedKey }) else {
            reference = nil
            return
        }
        reference = SSHAgentKeyReference(socketPath: socketPath, identity: identity)
    }
}
