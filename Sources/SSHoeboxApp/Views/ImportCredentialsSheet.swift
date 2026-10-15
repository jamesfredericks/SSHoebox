import SwiftUI
import SSHoeboxCore
import CryptoKit
import UniformTypeIdentifiers

/// Imports hosts+credentials from a CSV file or a Bitwarden JSON export.
struct ImportCredentialsSheet: View {
    @ObservedObject var viewModel: HostsViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var showFilePicker = false
    @State private var parsedEntries: [ImportEntry] = []
    @State private var selected: Set<UUID> = []
    @State private var parseError: String? = nil
    @State private var importDone = false
    @State private var importedCount = 0

    typealias ImportEntry = CredentialImportEntry

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 10) {
                Image(systemName: "arrow.down.doc")
                    .font(.system(size: 18))
                    .foregroundStyle(DesignSystem.Colors.accent)
                Text("Import Hosts & Credentials")
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

            if importDone {
                importSuccessView
            } else if let error = parseError {
                errorView(error)
            } else if parsedEntries.isEmpty {
                pickFileView
            } else {
                selectionView
            }
        }
        .frame(width: 520, height: 520)
        .background(DesignSystem.Colors.background)
        .fileImporter(
            isPresented: $showFilePicker,
            allowedContentTypes: [.json, .commaSeparatedText, .text],
            allowsMultipleSelection: false
        ) { result in
            handleFilePick(result)
        }
    }

    // MARK: - Sub-views

    private var pickFileView: some View {
        VStack(spacing: 20) {
            Image(systemName: "doc.badge.plus")
                .font(.system(size: 52))
                .foregroundStyle(DesignSystem.Colors.accent.opacity(0.5))

            Text("Select a file to import")
                .font(DesignSystem.Typography.heading())
                .foregroundStyle(DesignSystem.Colors.textPrimary)

            VStack(alignment: .leading, spacing: 8) {
                formatRow(icon: "tablecells", label: "CSV", detail: "Bitwarden, 1Password, LastPass, Chrome or Firefox export, or name, hostname, port, username, password")
                formatRow(icon: "shield", label: "Bitwarden JSON", detail: "Bitwarden export (all items)")
            }
            .padding(.horizontal, 32)

            Button("Choose File…") { showFilePicker = true }
                .buttonStyle(.borderedProminent)
                .tint(DesignSystem.Colors.accent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func formatRow(icon: String, label: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(DesignSystem.Colors.accent)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(DesignSystem.Typography.body()).foregroundStyle(DesignSystem.Colors.textPrimary)
                Text(detail).font(.caption).foregroundStyle(DesignSystem.Colors.textSecondary)
            }
        }
    }

    private var selectionView: some View {
        VStack(spacing: 0) {
            List {
                ForEach(parsedEntries) { entry in
                    HStack(spacing: 10) {
                        Image(systemName: selected.contains(entry.id) ? "checkmark.circle.fill" : "circle")
                            .foregroundStyle(selected.contains(entry.id) ? DesignSystem.Colors.accent : DesignSystem.Colors.textSecondary)
                            .onTapGesture { toggleSelection(entry.id) }

                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.name)
                                .font(DesignSystem.Typography.body())
                                .foregroundStyle(DesignSystem.Colors.textPrimary)
                            Text("\(entry.username.isEmpty ? "" : "\(entry.username)@")\(entry.hostname):\(entry.port)")
                                .font(DesignSystem.Typography.mono())
                                .foregroundStyle(DesignSystem.Colors.textSecondary)
                        }
                        Spacer()
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { toggleSelection(entry.id) }
                    .padding(.vertical, 2)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background(DesignSystem.Colors.background)

            Divider()

            HStack {
                Button(selected.count == parsedEntries.count ? "Deselect All" : "Select All") {
                    if selected.count == parsedEntries.count {
                        selected.removeAll()
                    } else {
                        selected = Set(parsedEntries.map(\.id))
                    }
                }
                .buttonStyle(.plain)
                .foregroundStyle(DesignSystem.Colors.accent)
                .font(DesignSystem.Typography.label())

                Spacer()

                Text("\(selected.count) of \(parsedEntries.count) selected")
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)

                Button("Import") { performImport() }
                    .buttonStyle(.borderedProminent)
                    .disabled(selected.isEmpty)
            }
            .padding(DesignSystem.Spacing.large)
        }
    }

    private var importSuccessView: some View {
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
    }

    private func errorView(_ message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle").font(.system(size: 36)).foregroundStyle(.orange)
            Text(message).font(DesignSystem.Typography.body()).foregroundStyle(DesignSystem.Colors.textSecondary).multilineTextAlignment(.center)
            Button("Choose Another File") {
                parseError = nil
                parsedEntries = []
                showFilePicker = true
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    // MARK: - Actions

    private func toggleSelection(_ id: UUID) {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }
        // Not sandboxed, so the URL may not be security-scoped; read it either way
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let content: String
        do {
            content = try String(contentsOf: url, encoding: .utf8)
        } catch {
            parseError = "Failed to read file: \(error.localizedDescription)"
            return
        }

        do {
            parsedEntries = try CredentialImporter.parse(content, fileExtension: url.pathExtension)
            selected = Set(parsedEntries.map(\.id))
            if parsedEntries.isEmpty {
                parseError = "No importable entries found in the selected file."
            }
        } catch {
            parseError = error.localizedDescription
        }
    }

    private func performImport() {
        let toImport = parsedEntries.filter { selected.contains($0.id) }
        for entry in toImport {
            viewModel.addHost(
                name: entry.name,
                hostname: entry.hostname,
                port: entry.port,
                protocolType: "ssh",
                user: entry.username,
                credentialType: entry.password.isEmpty ? "none" : "password",
                credentialSecret: entry.password
            )
        }
        importedCount = toImport.count
        importDone = true
    }
}
