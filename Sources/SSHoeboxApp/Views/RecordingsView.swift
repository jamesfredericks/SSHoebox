import SwiftUI
import AppKit
import CryptoKit
import SSHoeboxCore

/// Settings → Recordings: the encrypted session recordings, decrypted in memory to read.
struct RecordingsView: View {
    let vaultKey: SymmetricKey

    @State private var recordings: [SessionRecording.Summary] = []
    @State private var selectedURL: URL?
    @State private var contents: SessionRecordingReader.Contents?
    @State private var readError: String?
    @State private var search = ""
    @State private var toDelete: SessionRecording.Summary?
    @State private var confirmExport = false

    private var selected: SessionRecording.Summary? { recordings.first { $0.url == selectedURL } }

    var body: some View {
        HSplitView {
            list
                .frame(minWidth: 240, idealWidth: 280, maxWidth: 380)
            detail
                .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(DesignSystem.Colors.background)
        .navigationTitle("Recordings")
        .toolbar {
            ToolbarItem {
                Button { reload() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .help("Refresh")
            }
        }
        .onAppear(perform: reload)
        .onChange(of: selectedURL) { _, _ in open() }
        .alert("Delete this recording?", isPresented: Binding(get: { toDelete != nil }, set: { if !$0 { toDelete = nil } })) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) { delete() }
        } message: {
            Text("It's removed from the recordings folder. This can't be undone.")
        }
        .alert("Export as plain text?", isPresented: $confirmExport) {
            Button("Cancel", role: .cancel) {}
            Button("Export…") { export() }
        } message: {
            Text("The exported file is NOT encrypted: anyone who can read it sees everything the session showed. Only export to somewhere you trust, and delete it when you're done.")
        }
    }

    // MARK: - List

    private var list: some View {
        VStack(spacing: 0) {
            if recordings.isEmpty {
                EmptyStateView(title: "No Recordings",
                               description: "Record a terminal session from its record button, or turn on recording for every session in Preferences.",
                               systemImage: "record.circle")
                    .frame(maxHeight: .infinity)
            } else {
                List(recordings, selection: $selectedURL) { recording in
                    VStack(alignment: .leading, spacing: 2) {
                        if let metadata = recording.metadata {
                            Text(metadata.hostName).foregroundStyle(DesignSystem.Colors.textPrimary)
                            Text(metadata.startedAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.caption)
                                .foregroundStyle(DesignSystem.Colors.textSecondary)
                        } else {
                            Label(recording.url.lastPathComponent, systemImage: "lock.trianglebadge.exclamationmark")
                                .foregroundStyle(DesignSystem.Colors.textSecondary)
                            Text("Can't be opened with this vault")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                        Text(ByteCountFormatter.string(fromByteCount: Int64(recording.fileSize), countStyle: .file))
                            .font(.caption2)
                            .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.7))
                    }
                    .padding(.vertical, 2)
                    .tag(recording.url)
                    .contextMenu {
                        Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([recording.url]) }
                        Button("Delete…", role: .destructive) { toDelete = recording }
                    }
                }
            }
            Divider()
            HStack {
                Image(systemName: "lock.fill").font(.caption)
                Text("Encrypted with your vault key")
                    .font(.caption)
                Spacer()
                Button("Folder") {
                    let folder = SessionRecording.directory
                    try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                    NSWorkspace.shared.open(folder)
                }
                .font(.caption)
            }
            .foregroundStyle(DesignSystem.Colors.textSecondary)
            .padding(8)
        }
    }

    // MARK: - Detail

    @ViewBuilder
    private var detail: some View {
        if let readError {
            EmptyStateView(title: "Can't Open Recording", description: readError, systemImage: "lock.trianglebadge.exclamationmark")
        } else if let contents {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(contents.metadata.hostName).font(DesignSystem.Typography.heading())
                        Text("\(contents.metadata.endpoint) · \(contents.metadata.startedAt.formatted(date: .abbreviated, time: .standard))"
                             + (contents.endedAt.map { " – \($0.formatted(date: .omitted, time: .standard))" } ?? ""))
                            .font(.caption)
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                        if !contents.isComplete {
                            Text("Incomplete: the recording stopped before its end (the app quit while recording, or the file is damaged).")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                    Spacer()
                    TextField("Find", text: $search)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 180)
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(contents.text, forType: .string)
                    } label: { Label("Copy", systemImage: "doc.on.doc") }
                        .help("Copy the whole transcript")
                    Button { confirmExport = true } label: { Label("Export…", systemImage: "square.and.arrow.up") }
                        .help("Save a plain-text (unencrypted) copy")
                    Button(role: .destructive) { toDelete = selected } label: { Image(systemName: "trash") }
                        .help("Delete this recording")
                }
                .padding(DesignSystem.Spacing.medium)
                Divider()
                ScrollView([.vertical, .horizontal]) {
                    Text(highlighted(contents.text))
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(DesignSystem.Spacing.medium)
                }
                .background(Color(red: 0.05, green: 0.05, blue: 0.08))
                if !search.isEmpty {
                    Divider()
                    Text("\(matchCount(in: contents.text)) match\(matchCount(in: contents.text) == 1 ? "" : "es")")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                        .padding(6)
                }
            }
        } else {
            EmptyStateView(title: "Select a Recording", description: "Recordings are decrypted only to show them here.",
                           systemImage: "doc.text.magnifyingglass")
        }
    }

    private func highlighted(_ text: String) -> AttributedString {
        var attributed = AttributedString(text)
        attributed.foregroundColor = Color(white: 0.85)
        guard !search.isEmpty else { return attributed }
        var range = attributed.startIndex..<attributed.endIndex
        while let found = attributed[range].range(of: search, options: .caseInsensitive) {
            attributed[found].backgroundColor = .yellow.opacity(0.6)
            attributed[found].foregroundColor = .black
            range = found.upperBound..<attributed.endIndex
        }
        return attributed
    }

    private func matchCount(in text: String) -> Int {
        guard !search.isEmpty else { return 0 }
        return text.lowercased().components(separatedBy: search.lowercased()).count - 1
    }

    // MARK: - Actions

    private func reload() {
        recordings = SessionRecording.list(vaultKey: vaultKey)
        if let selectedURL, !recordings.contains(where: { $0.url == selectedURL }) {
            self.selectedURL = nil
            contents = nil
        }
    }

    private func open() {
        contents = nil
        readError = nil
        search = ""
        guard let selectedURL else { return }
        do {
            contents = try SessionRecordingReader.read(selectedURL, vaultKey: vaultKey)
        } catch {
            readError = error.localizedDescription
        }
    }

    private func delete() {
        guard let recording = toDelete else { return }
        toDelete = nil
        try? FileManager.default.removeItem(at: recording.url)
        if selectedURL == recording.url {
            selectedURL = nil
            contents = nil
        }
        reload()
    }

    private func export() {
        guard let contents else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(contents.metadata.hostName) \(contents.metadata.startedAt.formatted(.iso8601.year().month().day())).txt"
        panel.message = "This copy is not encrypted."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let header = "SSHoebox session recording\nHost:    \(contents.metadata.hostName) (\(contents.metadata.endpoint))\n"
            + "Started: \(contents.metadata.startedAt.formatted(.iso8601))\n\n"
        try? Data((header + contents.text).utf8).write(to: url, options: .atomic)
        LoginTrace.event("recording: exported a plain-text copy of a \(contents.metadata.hostName) recording")
    }
}
