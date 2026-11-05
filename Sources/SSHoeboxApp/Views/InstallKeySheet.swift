import SwiftUI
import CryptoKit
import SSHoeboxCore

/// Adds a credential's public key to a server's ~/.ssh/authorized_keys (like ssh-copy-id),
/// logging in with that server's own saved credential, or through an open terminal session.
struct InstallKeySheet: View {
    let publicKeyLine: String
    let keyName: String
    let initialHostId: String
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @EnvironmentObject private var registry: TerminalSessionRegistry
    @Environment(\.dismiss) private var dismiss

    private enum Status: Equatable {
        case idle
        case working
        case done(String)
        case failed(String)
    }

    @State private var hosts: [SavedHost] = []
    @State private var hostId: String = ""
    @State private var status: Status = .idle

    private var selectedHost: SavedHost? { hosts.first { $0.id == hostId } }

    /// A connected terminal session to the chosen host, which is used instead of a new login.
    private var openSession: TerminalSession? {
        registry.existingStore(for: hostId)?.sessions.first { $0.manager.connectionState == .connected }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DesignSystem.Spacing.medium) {
            Text("Install Public Key on Server")
                .font(DesignSystem.Typography.heading())
            Text("Adds the public half of \(keyName) to ~/.ssh/authorized_keys on the server, so the key can log in. The private key never leaves this Mac.")
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            Text(publicKeyLine)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(3)
                .truncationMode(.middle)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 6).fill(DesignSystem.Colors.surface))

            Picker("Server", selection: $hostId) {
                ForEach(hosts) { host in
                    Text(host.decryptedName(using: vaultKey)).tag(host.id)
                }
            }
            .onChange(of: hostId) { status = .idle }

            Text(loginDescription)
                .font(.caption)
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            switch status {
            case .idle:
                EmptyView()
            case .working:
                HStack { ProgressView().controlSize(.small); Text("Installing…") }
            case .done(let message):
                Label(message, systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            case .failed(let message):
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Copy Public Key") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(publicKeyLine, forType: .string)
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Install") { Task { await install() } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(selectedHost == nil || status == .working)
            }
        }
        .padding(DesignSystem.Spacing.large)
        .frame(width: 520)
        .onAppear {
            hosts = ((try? HostRepository(dbManager: dbManager).getAll()) ?? [])
                .sorted { $0.decryptedName(using: vaultKey).localizedCaseInsensitiveCompare($1.decryptedName(using: vaultKey)) == .orderedAscending }
            hostId = initialHostId
        }
    }

    private var loginDescription: String {
        guard let host = selectedHost else { return "" }
        if openSession != nil {
            return "Uses the open terminal session to \(host.decryptedName(using: vaultKey))."
        }
        let login = HostConnectionPlanner(dbManager: dbManager, vaultKey: vaultKey).login(for: host)
        let method: String
        switch login.auth {
        case .password: method = "its saved password"
        case .privateKey: method = "its saved private key"
        case .agentKey: method = "its SSH agent key"
        case .interactive: method = "keyboard-interactive, which can't be answered here: open a terminal session to it first"
        }
        return "Logs in to \(login.endpoint) with \(method)."
    }

    private func install() async {
        guard let host = selectedHost else { return }
        status = .working
        do {
            let command = try AuthorizedKeys.installCommand(for: publicKeyLine)
            let output: String
            if let session = openSession {
                output = try await session.manager.run(command)
            } else {
                let plan = try HostConnectionPlanner(dbManager: dbManager, vaultKey: vaultKey).plan(for: host)
                output = try await SSHCommandRunner.run(command, target: plan.target, via: plan.jumps,
                                                        repository: KnownHostRepository(dbManager: dbManager),
                                                        purpose: "install public key")
            }
            switch AuthorizedKeys.parse(output: output) {
            case .added?: status = .done("Added to ~/.ssh/authorized_keys on \(host.decryptedName(using: vaultKey)).")
            case .alreadyPresent?: status = .done("The key was already in authorized_keys.")
            case nil: status = .failed("The server didn't confirm the change. Output: \(output.prefix(200))")
            }
        } catch {
            status = .failed((error as? LocalizedError)?.errorDescription ?? String(describing: error))
        }
    }
}
