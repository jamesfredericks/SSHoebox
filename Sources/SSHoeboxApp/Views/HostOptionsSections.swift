import SwiftUI
import SSHoeboxCore

/// The connection and organizing options of a host, as Form sections. Used by the Add Host
/// and Edit Host sheets.
struct HostOptionsSections: View {
    @Binding var options: HostOptions
    /// Hosts that can be the jump host (everything but the host being edited).
    let jumpCandidates: [(id: String, name: String)]

    @State private var tagsText = ""
    @State private var didLoadTags = false

    /// Interval choices; nil means the Preferences default.
    private static let keepAliveChoices: [Int?] = [nil, 0, 15, 30, 60, 120, 300]

    var body: some View {
        Group {
            Section {
                Picker("Jump host", selection: $options.jumpHostId) {
                    Text("None (connect directly)").tag(String?.none)
                    ForEach(jumpCandidates, id: \.id) { candidate in
                        Text(candidate.name).tag(Optional(candidate.id))
                    }
                }
                Picker("Keep-alive", selection: $options.keepAliveInterval) {
                    ForEach(Self.keepAliveChoices, id: \.self) { choice in
                        Text(Self.label(for: choice)).tag(choice)
                    }
                }
                LabeledContent("Startup command") {
                    TextField("Startup command", text: Binding(
                        get: { options.startupCommand ?? "" },
                        set: { options.startupCommand = $0.isEmpty ? nil : $0 }
                    ), prompt: Text("e.g. sudo -i, or cd /var/log"))
                        .labelsHidden()
                        .multilineTextAlignment(.trailing)
                        .font(DesignSystem.Typography.mono())
                        .autocorrectionDisabled()
                }
            } header: {
                Text("Connection")
            } footer: {
                Text("A jump host is connected to first, and this host is reached through it (ssh -J). It uses its own saved credentials. The startup command is typed into the shell when a terminal opens.")
                    .font(.caption)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }

            Section {
                ForEach($options.portForwards) { $forward in
                    PortForwardRow(forward: $forward) {
                        options.portForwards.removeAll { $0.id == forward.id }
                    }
                }
                Button {
                    options.portForwards.append(PortForward(localPort: 8080, remoteHost: "localhost", remotePort: 80))
                } label: {
                    Label("Add Tunnel", systemImage: "plus")
                }
            } header: {
                Text("Tunnels (local port forwards)")
            } footer: {
                Text("Connections to the local port on this Mac are carried through SSH to the destination, as the server sees it (ssh -L). Tunnels marked Auto open with the first terminal session; start the others from the terminal's tunnel menu.")
                    .font(.caption)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }

            Section("Organize") {
                Toggle("Favorite", isOn: $options.isFavorite)
                TextField("Tags", text: $tagsText, prompt: Text("Comma-separated, e.g. prod, web"))
                    .autocorrectionDisabled()
                    .onChange(of: tagsText) { _, text in options.tags = HostOptions.tags(fromList: text) }
            }
        }
        .onAppear {
            guard !didLoadTags else { return }
            didLoadTags = true
            tagsText = options.tags.joined(separator: ", ")
        }
    }

    static func label(for interval: Int?) -> String {
        switch interval {
        case nil: return "Default (\(intervalText(SSHSessionOptions.preferredKeepAliveInterval)))"
        case 0?: return "Off"
        case let seconds?: return "Every \(intervalText(seconds))"
        }
    }

    static func intervalText(_ seconds: Int) -> String {
        if seconds == 0 { return "off" }
        return seconds % 60 == 0 ? "\(seconds / 60) min" : "\(seconds) s"
    }

    /// Whether every tunnel has valid ports and a destination.
    static func forwardsAreValid(_ options: HostOptions) -> Bool {
        options.portForwards.allSatisfy(\.isValid)
    }
}

private struct PortForwardRow: View {
    @Binding var forward: PortForward
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            TextField("Local", value: $forward.localPort, format: .number.grouping(.never))
                .frame(width: 64)
                .help("Port on this Mac (127.0.0.1)")
            Image(systemName: "arrow.right")
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            TextField("Destination host", text: $forward.remoteHost)
                .autocorrectionDisabled()
                .help("Host as the server sees it, e.g. localhost or db.internal")
            Text(":")
            TextField("Port", value: $forward.remotePort, format: .number.grouping(.never))
                .frame(width: 64)
            Toggle("Auto", isOn: $forward.autoStart)
                .toggleStyle(.checkbox)
                .help("Open with the first terminal session")
            Button(role: .destructive, action: onDelete) {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .help("Remove this tunnel")
        }
        .labelsHidden()
        .font(DesignSystem.Typography.mono())
        .overlay(alignment: .bottomLeading) {
            if !forward.isValid {
                Text("Ports must be 1–65535 and the destination can't be empty.")
                    .font(.caption2)
                    .foregroundStyle(.red)
                    .offset(y: 14)
            }
        }
        .padding(.bottom, forward.isValid ? 0 : 12)
    }
}
