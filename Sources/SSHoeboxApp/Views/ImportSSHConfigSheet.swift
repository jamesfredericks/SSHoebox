import SwiftUI
import SSHoeboxCore
import CryptoKit

/// Parses ~/.ssh/config and lets the user select which hosts to import.
struct ImportSSHConfigSheet: View {
    @ObservedObject var viewModel: HostsViewModel
    let vaultKey: SymmetricKey
    @Environment(\.dismiss) private var dismiss

    @State private var configHosts: [SSHConfigParser.ConfigHost] = []
    @State private var selected: Set<String> = []
    @State private var loadError: String? = nil
    @State private var importDone = false
    @State private var importedCount = 0

    private var defaultConfigURL: URL {
        URL(fileURLWithPath: (NSHomeDirectory() as NSString).appendingPathComponent(".ssh/config"))
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 10) {
                Image(systemName: "doc.text")
                    .font(.system(size: 18))
                    .foregroundStyle(DesignSystem.Colors.accent)
                Text("Import from ~/.ssh/config")
                    .font(DesignSystem.Typography.heading())
                Spacer()
                Button { dismiss() } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
                .buttonStyle(.plain)
            }
            .padding(DesignSystem.Spacing.large)

            Divider()

            if let error = loadError {
                VStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 36))
                        .foregroundStyle(.orange)
                    Text(error)
                        .font(DesignSystem.Typography.body())
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding()
            } else if importDone {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 40))
                        .foregroundStyle(.green)
                    Text("Imported \(importedCount) host\(importedCount == 1 ? "" : "s").")
                        .font(DesignSystem.Typography.heading())
                    Button("Done") { dismiss() }
                        .buttonStyle(.borderedProminent)
                        .padding(.top, 8)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if configHosts.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "tray")
                        .font(.system(size: 36))
                        .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.4))
                    Text("No named hosts found in ~/.ssh/config")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding()
            } else {
                // Selection list
                List {
                    ForEach(configHosts, id: \.alias) { host in
                        HStack(spacing: 10) {
                            Image(systemName: selected.contains(host.alias) ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(selected.contains(host.alias) ? DesignSystem.Colors.accent : DesignSystem.Colors.textSecondary)
                                .onTapGesture { toggleSelection(host.alias) }

                            VStack(alignment: .leading, spacing: 2) {
                                Text(host.alias)
                                    .font(DesignSystem.Typography.body())
                                    .foregroundStyle(DesignSystem.Colors.textPrimary)
                                let detail = [
                                    host.user.isEmpty ? nil : host.user,
                                    host.hostname,
                                    host.port != 22 ? ":\(host.port)" : nil
                                ].compactMap { $0 }.joined(separator: "@").replacingOccurrences(of: "@:", with: ":")
                                Text(detail)
                                    .font(DesignSystem.Typography.mono())
                                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                            }
                            Spacer()
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { toggleSelection(host.alias) }
                        .padding(.vertical, 2)
                    }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
                .background(DesignSystem.Colors.background)

                Divider()

                HStack {
                    Button(selected.count == configHosts.count ? "Deselect All" : "Select All") {
                        if selected.count == configHosts.count {
                            selected.removeAll()
                        } else {
                            selected = Set(configHosts.map(\.alias))
                        }
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(DesignSystem.Colors.accent)
                    .font(DesignSystem.Typography.label())

                    Spacer()

                    Text("\(selected.count) of \(configHosts.count) selected")
                        .font(DesignSystem.Typography.label())
                        .foregroundStyle(DesignSystem.Colors.textSecondary)

                    Button("Import Selected") {
                        performImport()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(selected.isEmpty)
                }
                .padding(DesignSystem.Spacing.large)
            }
        }
        .frame(width: 460, height: 480)
        .background(DesignSystem.Colors.background)
        .onAppear { loadConfig() }
    }

    private func toggleSelection(_ alias: String) {
        if selected.contains(alias) {
            selected.remove(alias)
        } else {
            selected.insert(alias)
        }
    }

    private func loadConfig() {
        guard FileManager.default.fileExists(atPath: defaultConfigURL.path) else {
            loadError = "~/.ssh/config not found."
            return
        }
        do {
            configHosts = try SSHConfigParser.parse(contentsOf: defaultConfigURL)
            selected = Set(configHosts.map(\.alias))
        } catch {
            loadError = "Could not read ~/.ssh/config: \(error.localizedDescription)"
        }
    }

    private func performImport() {
        let toImport = configHosts.filter { selected.contains($0.alias) }
        var count = 0
        for entry in toImport {
            viewModel.addHost(
                name: entry.alias,
                hostname: entry.hostname,
                port: entry.port,
                protocolType: "ssh",
                user: entry.user
            )
            count += 1
        }
        importedCount = count
        importDone = true
    }
}
