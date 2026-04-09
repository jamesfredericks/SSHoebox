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
    @State private var fileType: FileFormat = .unknown

    enum FileFormat { case csv, bitwardenJSON, unknown }

    struct ImportEntry: Identifiable {
        let id = UUID()
        let name: String
        let hostname: String
        let port: Int
        let username: String
        let password: String
        let notes: String
    }

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
                formatRow(icon: "tablecells", label: "CSV", detail: "name, hostname, port, username, password")
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
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }

        do {
            let content = try String(contentsOf: url, encoding: .utf8)
            let ext = url.pathExtension.lowercased()

            if ext == "json" {
                parsedEntries = try parseBitwardenJSON(content)
                fileType = .bitwardenJSON
            } else {
                parsedEntries = parseCSV(content)
                fileType = .csv
            }

            selected = Set(parsedEntries.map(\.id))
            if parsedEntries.isEmpty {
                parseError = "No importable entries found in the selected file."
            }
        } catch {
            parseError = "Failed to read file: \(error.localizedDescription)"
        }
    }

    private func parseCSV(_ content: String) -> [ImportEntry] {
        var entries: [ImportEntry] = []
        let lines = content.components(separatedBy: .newlines).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        guard lines.count > 1 else { return [] }

        for line in lines.dropFirst() { // skip header row
            let cols = splitCSVLine(line)
            guard cols.count >= 2 else { continue }
            let name = cols[0]
            let hostname = cols[1]
            let port = cols.count > 2 ? (Int(cols[2]) ?? 22) : 22
            let username = cols.count > 3 ? cols[3] : ""
            let password = cols.count > 4 ? cols[4] : ""
            entries.append(ImportEntry(name: name, hostname: hostname, port: port, username: username, password: password, notes: ""))
        }
        return entries
    }

    private func splitCSVLine(_ line: String) -> [String] {
        var result: [String] = []
        var current = ""
        var inQuotes = false
        for char in line {
            if char == "\"" { inQuotes.toggle() }
            else if char == "," && !inQuotes { result.append(current); current = "" }
            else { current.append(char) }
        }
        result.append(current)
        return result.map { $0.trimmingCharacters(in: .init(charactersIn: " \"")) }
    }

    private func parseBitwardenJSON(_ content: String) throws -> [ImportEntry] {
        guard let data = content.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let items = root["items"] as? [[String: Any]] else {
            throw ImportError.invalidFormat
        }

        var entries: [ImportEntry] = []
        for item in items {
            guard item["type"] as? Int == 1 else { continue } // type 1 = Login
            let name = item["name"] as? String ?? "Unnamed"
            guard let login = item["login"] as? [String: Any] else { continue }
            let username = login["username"] as? String ?? ""
            let password = login["password"] as? String ?? ""
            let uris = (login["uris"] as? [[String: Any]])?.compactMap { $0["uri"] as? String } ?? []
            let rawURI = uris.first ?? ""

            // Try to parse URI as hostname:port
            var hostname = rawURI
            var port = 22
            if let url = URLComponents(string: rawURI), let host = url.host {
                hostname = host
                port = url.port ?? 22
            }
            if hostname.isEmpty { continue }

            entries.append(ImportEntry(name: name, hostname: hostname, port: port, username: username, password: password, notes: ""))
        }
        return entries
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

    enum ImportError: Error {
        case invalidFormat
    }
}
