import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SSHoeboxCore

// MARK: - SFTPBrowserView

struct SFTPBrowserView: View {
    @ObservedObject var sftp: SFTPSessionManager
    @State private var showHidden = false
    @State private var showingNewFolder = false
    @State private var newFolderName = ""
    @State private var entryToRename: SFTPEntry? = nil
    @State private var renameText = ""
    @State private var statusMessage: String? = nil
    @State private var passphraseInput = ""
    @State private var selection = Set<SFTPEntry.ID>()
    @State private var entriesToDelete: [SFTPEntry] = []
    @State private var isDropTargeted = false
    @Environment(\.openWindow) private var openWindow

    var displayedEntries: [SFTPEntry] {
        showHidden ? sftp.entries : sftp.entries.filter { !$0.isHidden }
    }

    var body: some View {
        VStack(spacing: 0) {
            controlBar
            Divider()

            ZStack {
                switch sftp.connectionState {
                case .connecting:
                    connectingView
                case .failed(let msg):
                    failedView(message: msg)
                case .connected, .disconnected:
                    fileListView
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            if !sftp.transfers.isEmpty {
                Divider()
                SFTPTransfersPanel(sftp: sftp)
            }

            if sftp.errorMessage != nil || statusMessage != nil {
                Divider()
                bottomStatusBar
            }
        }
        .background(DesignSystem.Colors.background)
        .onDisappear {
            sftp.disconnect()
        }
        .sheet(item: $sftp.passphraseChallenge) { challenge in
            sftpPassphraseSheet(challenge: challenge)
        }
        .sheet(isPresented: $showingNewFolder) {
            newFolderSheet
        }
        .sheet(item: $entryToRename) { entry in
            renameSheet(for: entry)
        }
        .alert("Delete \(entriesToDelete.count == 1 ? "“\(entriesToDelete[0].filename)”" : "\(entriesToDelete.count) items")?",
               isPresented: Binding(get: { !entriesToDelete.isEmpty }, set: { if !$0 { entriesToDelete = [] } })) {
            Button("Cancel", role: .cancel) { entriesToDelete = [] }
            Button("Delete", role: .destructive) {
                let doomed = entriesToDelete
                entriesToDelete = []
                Task { await deleteEntries(doomed) }
            }
        } message: {
            Text(entriesToDelete.contains(where: \.isDirectory)
                 ? "Folders are deleted with everything in them. This can't be undone."
                 : "This can't be undone.")
        }
        .onChange(of: sftp.currentPath) { selection = [] }
    }

    @ViewBuilder
    private func entryMenu(_ items: [SFTPEntry]) -> some View {
        if !items.isEmpty {
            if items.count == 1, let folder = items.first, folder.isDirectory {
                Button {
                    Task { await sftp.navigate(to: folder.path) }
                } label: {
                    Label("Open", systemImage: "folder")
                }
            }
            Button {
                chooseDownloadFolder(for: items)
            } label: {
                Label(items.count == 1 ? "Download…" : "Download \(items.count) Items…", systemImage: "square.and.arrow.down")
            }
            Button {
                sftp.download(items, to: Self.downloadsFolder)
                flash("Downloading to Downloads…")
            } label: {
                Label("Download to Downloads", systemImage: "arrow.down.circle")
            }
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(items.map(\.path).joined(separator: "\n"), forType: .string)
            } label: {
                Label(items.count == 1 ? "Copy Path" : "Copy Paths", systemImage: "doc.on.doc")
            }
            if items.count == 1, let entry = items.first {
                Button {
                    renameText = entry.filename
                    entryToRename = entry
                } label: {
                    Label("Rename…", systemImage: "pencil")
                }
            }
            Divider()
            Button(role: .destructive) {
                entriesToDelete = items
            } label: {
                Label(items.count == 1 ? "Delete…" : "Delete \(items.count) Items…", systemImage: "trash")
            }
        }
    }

    private var selectedEntries: [SFTPEntry] {
        displayedEntries.filter { selection.contains($0.id) }
    }


    // MARK: - Control Bar (breadcrumb + action buttons)

    private var controlBar: some View {
        HStack(spacing: 0) {
            // Breadcrumb
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(Array(pathComponents(sftp.currentPath).enumerated()), id: \.offset) { i, component in
                        if i > 0 {
                            Image(systemName: "chevron.right")
                                .font(.system(size: 10, weight: .medium))
                                .foregroundStyle(DesignSystem.Colors.textSecondary)
                        }
                        Button(component.label) {
                            Task { await sftp.navigate(to: component.path) }
                        }
                        .buttonStyle(.plain)
                        .font(DesignSystem.Typography.label())
                        .foregroundStyle(
                            i == pathComponents(sftp.currentPath).count - 1
                                ? DesignSystem.Colors.textPrimary
                                : DesignSystem.Colors.accent
                        )
                        .disabled(i == pathComponents(sftp.currentPath).count - 1)
                    }
                }
                .padding(.horizontal, DesignSystem.Spacing.medium)
                .padding(.vertical, 8)
            }

            Spacer(minLength: 8)

            // Action buttons
            HStack(spacing: 2) {
                controlButton(
                    icon: showHidden ? "eye.slash" : "eye",
                    help: showHidden ? "Hide dotfiles" : "Show dotfiles"
                ) {
                    showHidden.toggle()
                }

                controlButton(
                    icon: "folder.badge.plus",
                    help: "New folder"
                ) {
                    showingNewFolder = true
                }
                .disabled(sftp.connectionState != .connected)

                controlButton(
                    icon: "square.and.arrow.up",
                    help: "Upload files or folders (or drop them on the list)"
                ) {
                    chooseUploads()
                }
                .disabled(sftp.connectionState != .connected)

                controlButton(
                    icon: "square.and.arrow.down",
                    help: "Download the selected items"
                ) {
                    chooseDownloadFolder(for: selectedEntries)
                }
                .disabled(sftp.connectionState != .connected || selection.isEmpty)

                controlButton(
                    icon: "trash",
                    help: "Delete the selected items"
                ) {
                    entriesToDelete = selectedEntries
                }
                .disabled(sftp.connectionState != .connected || selection.isEmpty)

                controlButton(
                    icon: "arrow.clockwise",
                    help: "Refresh"
                ) {
                    Task { await sftp.refresh() }
                }
                .disabled(sftp.connectionState != .connected)
            }
            .padding(.trailing, DesignSystem.Spacing.medium)
        }
        .background(DesignSystem.Colors.surface)
    }

    private func controlButton(icon: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .frame(width: 28, height: 28)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(DesignSystem.Colors.textSecondary)
        .help(help)
    }

    // MARK: - File List

    private var fileListView: some View {
        Group {
            if sftp.isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if displayedEntries.isEmpty {
                EmptyStateView(
                    title: "Empty Folder",
                    description: "This folder contains no items.",
                    systemImage: "folder"
                )
            } else {
                List(displayedEntries, selection: $selection) { entry in
                    SFTPEntryRow(entry: entry)
                }
                // SwiftUI passes the selection when the clicked row is selected, else that row.
                .contextMenu(forSelectionType: SFTPEntry.ID.self) { ids in
                    entryMenu(displayedEntries.filter { ids.contains($0.id) })
                } primaryAction: { ids in
                    // Double-click or Return: open a folder, download files.
                    let chosen = displayedEntries.filter { ids.contains($0.id) }
                    if chosen.count == 1, let folder = chosen.first, folder.isDirectory {
                        Task { await sftp.navigate(to: folder.path) }
                    } else if !chosen.isEmpty {
                        chooseDownloadFolder(for: chosen)
                    }
                }
                .listStyle(.plain)
            }
        }
        .background(DesignSystem.Colors.background)
        .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
            handleDrop(providers)
        }
        .overlay {
            if isDropTargeted {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(DesignSystem.Colors.accent, style: StrokeStyle(lineWidth: 2, dash: [6]))
                    .background(DesignSystem.Colors.accent.opacity(0.06))
                    .overlay(Label("Upload to \(sftp.currentPath)", systemImage: "square.and.arrow.up")
                        .padding(8)
                        .background(Capsule().fill(DesignSystem.Colors.surface)))
                    .padding(6)
                    .allowsHitTesting(false)
            }
        }
    }

    // MARK: - State Views

    private var connectingView: some View {
        VStack(spacing: 16) {
            ProgressView()
            Text("Connecting…")
                .font(DesignSystem.Typography.body())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func failedView(message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("Connection Failed")
                .font(DesignSystem.Typography.heading())
                .foregroundStyle(DesignSystem.Colors.textPrimary)
            Text(message)
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button("View Login Log") {
                OpenLoginLogAction(openWindow: openWindow)(attemptID: sftp.lastLoginAttemptID)
            }
            .help("Show what happened during this login")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Status Bar

    private var bottomStatusBar: some View {
        HStack(spacing: 6) {
            let isError = sftp.errorMessage != nil
            let message = sftp.errorMessage ?? statusMessage ?? ""
            Image(systemName: isError ? "exclamationmark.circle" : "info.circle")
                .font(.caption)
                .foregroundStyle(isError ? .red : DesignSystem.Colors.textSecondary)
            Text(message)
                .font(DesignSystem.Typography.label())
                .foregroundStyle(isError ? Color.red : DesignSystem.Colors.textSecondary)
                .lineLimit(1)
            Spacer()
            Text("\(displayedEntries.count) items")
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
        }
        .padding(.horizontal, DesignSystem.Spacing.medium)
        .padding(.vertical, 5)
        .background(DesignSystem.Colors.surface)
    }

    // MARK: - Sheets

    private func sftpPassphraseSheet(challenge: SSHPassphraseChallenge) -> some View {
        VStack(spacing: DesignSystem.Spacing.large) {
            Image(systemName: "lock.fill")
                .font(.system(size: 32))
                .foregroundStyle(DesignSystem.Colors.accent)

            Text("Key Passphrase Required")
                .font(DesignSystem.Typography.heading())

            Text("The private key for \(challenge.keyOwner.endpoint) is encrypted.\nEnter the passphrase to connect.")
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .multilineTextAlignment(.center)

            SecureField("Passphrase", text: $passphraseInput)
                .textFieldStyle(.roundedBorder)
                .onSubmit { submitSFTPPassphrase(challenge: challenge) }

            HStack(spacing: 12) {
                Button("Cancel") {
                    sftp.passphraseChallenge = nil
                    passphraseInput = ""
                }
                .buttonStyle(.plain)

                Spacer()

                Button("Connect") { submitSFTPPassphrase(challenge: challenge) }
                    .buttonStyle(.borderedProminent)
                    .disabled(passphraseInput.isEmpty)
            }
        }
        .padding(DesignSystem.Spacing.large)
        .frame(width: 340)
    }

    private func submitSFTPPassphrase(challenge: SSHPassphraseChallenge) {
        guard !passphraseInput.isEmpty else { return }
        let p = passphraseInput
        passphraseInput = ""
        sftp.passphraseChallenge = nil
        Task {
            await sftp.connect(answering: challenge, passphrase: p)
        }
    }

    private var newFolderSheet: some View {
        VStack(spacing: DesignSystem.Spacing.large) {
            Text("New Folder")
                .font(DesignSystem.Typography.heading())

            TextField("Folder name", text: $newFolderName)
                .textFieldStyle(.roundedBorder)
                .onSubmit { createFolder() }

            HStack {
                Button("Cancel") {
                    showingNewFolder = false
                    newFolderName = ""
                }
                .buttonStyle(.plain)
                Spacer()
                Button("Create") { createFolder() }
                    .buttonStyle(.borderedProminent)
                    .disabled(newFolderName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(DesignSystem.Spacing.large)
        .frame(width: 320)
    }

    private func renameSheet(for entry: SFTPEntry) -> some View {
        VStack(spacing: DesignSystem.Spacing.large) {
            Text("Rename")
                .font(DesignSystem.Typography.heading())

            TextField("New name", text: $renameText)
                .textFieldStyle(.roundedBorder)
                .onSubmit { performRename(entry: entry) }

            HStack {
                Button("Cancel") { entryToRename = nil }
                    .buttonStyle(.plain)
                Spacer()
                Button("Rename") { performRename(entry: entry) }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        renameText.trimmingCharacters(in: .whitespaces).isEmpty ||
                        renameText == entry.filename
                    )
            }
        }
        .padding(DesignSystem.Spacing.large)
        .frame(width: 320)
    }

    // MARK: - File Operations

    private func createFolder() {
        let name = newFolderName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        showingNewFolder = false
        newFolderName = ""
        Task {
            do {
                try await sftp.createDirectory(named: name)
                flash("Folder '\(name)' created.")
            } catch {
                sftp.errorMessage = "Couldn't create the folder: \(error.localizedDescription)"
            }
        }
    }

    private func performRename(entry: SFTPEntry) {
        let newName = renameText.trimmingCharacters(in: .whitespaces)
        guard !newName.isEmpty, newName != entry.filename else { return }
        entryToRename = nil
        Task {
            do {
                try await sftp.rename(entry: entry, to: newName)
                flash("Renamed to '\(newName)'.")
            } catch {
                sftp.errorMessage = "Couldn't rename: \(error.localizedDescription)"
            }
        }
    }

    static var downloadsFolder: URL {
        FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Downloads")
    }

    private func chooseDownloadFolder(for entries: [SFTPEntry]) {
        guard !entries.isEmpty else { return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Download Here"
        panel.message = entries.count == 1 ? "Choose where to save “\(entries[0].filename)”."
                                           : "Choose where to save \(entries.count) items."
        panel.directoryURL = Self.downloadsFolder
        guard panel.runModal() == .OK, let folder = panel.url else { return }
        sftp.download(entries, to: folder)
    }

    private func chooseUploads() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Upload"
        panel.message = "Choose files or folders to upload to \(sftp.currentPath)."
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        sftp.upload(panel.urls)
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        guard sftp.connectionState == .connected else { return false }
        let folder = sftp.currentPath
        for provider in providers where provider.canLoadObject(ofClass: URL.self) {
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url, url.isFileURL else { return }
                Task { @MainActor in sftp.upload([url], to: folder) }
            }
        }
        return true
    }

    private func deleteEntries(_ entries: [SFTPEntry]) async {
        do {
            try await sftp.delete(entries: entries)
            selection.subtract(entries.map(\.id))
            flash(entries.count == 1 ? "Deleted '\(entries[0].filename)'." : "Deleted \(entries.count) items.")
        } catch {
            sftp.errorMessage = "Delete failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Helpers

    private struct PathComponent {
        let label: String
        let path: String
    }

    private func pathComponents(_ path: String) -> [PathComponent] {
        var result: [PathComponent] = [PathComponent(label: "/", path: "/")]
        let parts = path.split(separator: "/", omittingEmptySubsequences: true)
        var built = ""
        for part in parts {
            built += "/\(part)"
            result.append(PathComponent(label: String(part), path: built))
        }
        return result
    }

    private func flash(_ msg: String) {
        statusMessage = msg
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            if statusMessage == msg { statusMessage = nil }
        }
    }
}

// MARK: - SFTPEntryRow

struct SFTPEntryRow: View {
    let entry: SFTPEntry

    var body: some View {
        HStack(spacing: DesignSystem.Spacing.medium) {
            Image(systemName: entry.systemImage)
                .font(.system(size: 15))
                .foregroundStyle(iconColor)
                .frame(width: 22, alignment: .center)

            Text(entry.filename)
                .font(DesignSystem.Typography.body())
                .foregroundStyle(DesignSystem.Colors.textPrimary)
                .lineLimit(1)

            Spacer()

            if !entry.isDirectory {
                Text(entry.formattedSize)
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .frame(width: 72, alignment: .trailing)
            }

            if let date = entry.modifiedDate {
                Text(date.formatted(date: .abbreviated, time: .omitted))
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .frame(width: 88, alignment: .trailing)
            }
        }
        .padding(.vertical, 3)
    }

    private var iconColor: Color {
        if entry.isDirectory { return Color(red: 0.9, green: 0.75, blue: 0.3) }
        if entry.isSymlink   { return DesignSystem.Colors.accent.opacity(0.7) }
        return DesignSystem.Colors.textSecondary
    }
}


// MARK: - Transfers Panel

/// Uploads and downloads with progress; cancel running ones, clear finished ones.
struct SFTPTransfersPanel: View {
    @ObservedObject var sftp: SFTPSessionManager

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Transfers")
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                Spacer()
                Button("Clear Finished") { sftp.clearFinishedTransfers() }
                    .buttonStyle(.plain)
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(DesignSystem.Colors.accent)
                    .disabled(!sftp.transfers.contains { !$0.isActive })
            }
            ScrollView {
                VStack(spacing: 4) {
                    ForEach(sftp.transfers.reversed()) { transfer in
                        row(transfer)
                    }
                }
            }
            .frame(maxHeight: 120)
        }
        .padding(.horizontal, DesignSystem.Spacing.medium)
        .padding(.vertical, 6)
        .background(DesignSystem.Colors.surface)
    }

    private func row(_ transfer: SFTPTransfer) -> some View {
        HStack(spacing: 8) {
            Image(systemName: transfer.direction == .upload ? "arrow.up.circle" : "arrow.down.circle")
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            Text(transfer.name)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: 160, alignment: .leading)
            switch transfer.state {
            case .queued:
                Text("Waiting…").foregroundStyle(DesignSystem.Colors.textSecondary)
                Spacer()
            case .running:
                if let fraction = transfer.fractionCompleted {
                    ProgressView(value: fraction)
                } else {
                    ProgressView().controlSize(.small)
                    Spacer()
                }
                Text(detail(transfer)).monospacedDigit().foregroundStyle(DesignSystem.Colors.textSecondary)
            case .finished:
                Label(detail(transfer), systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                Spacer()
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([transfer.localURL])
                } label: { Image(systemName: "magnifyingglass") }
                    .buttonStyle(.plain)
                    .help("Show in Finder")
                    .opacity(transfer.direction == .download ? 1 : 0)
            case .failed(let reason):
                Label(reason, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).lineLimit(1)
                Spacer()
            case .cancelled:
                Text("Cancelled").foregroundStyle(DesignSystem.Colors.textSecondary)
                Spacer()
            }
            if transfer.isActive {
                Button {
                    sftp.cancelTransfer(transfer.id)
                } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .help("Cancel")
            }
        }
        .font(DesignSystem.Typography.label())
    }

    private func detail(_ transfer: SFTPTransfer) -> String {
        let done = ByteCountFormatter.string(fromByteCount: Int64(transfer.transferredBytes), countStyle: .file)
        let files = transfer.fileCount > 1 ? " · \(transfer.filesDone)/\(transfer.fileCount) files" : ""
        guard let total = transfer.totalBytes else { return done + files }
        return "\(done) of \(ByteCountFormatter.string(fromByteCount: Int64(total), countStyle: .file))" + files
    }
}
