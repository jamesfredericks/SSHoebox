import SwiftUI
import AppKit
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
    @State private var showingFilePicker = false
    @State private var passphraseInput = ""

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
        .fileImporter(
            isPresented: $showingFilePicker,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            handleFilePick(result)
        }
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
                    help: "Upload file"
                ) {
                    showingFilePicker = true
                }
                .disabled(sftp.connectionState != .connected)

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
                List(displayedEntries) { entry in
                    SFTPEntryRow(entry: entry)
                        .contentShape(Rectangle())
                        .onTapGesture(count: 2) {
                            if entry.isDirectory {
                                Task { await sftp.navigate(to: entry.path) }
                            }
                        }
                        .contextMenu {
                            if !entry.isDirectory {
                                Button {
                                    downloadEntry(entry)
                                } label: {
                                    Label("Download…", systemImage: "square.and.arrow.down")
                                }
                            }

                            Button {
                                renameText = entry.filename
                                entryToRename = entry
                            } label: {
                                Label("Rename…", systemImage: "pencil")
                            }

                            Divider()

                            Button(role: .destructive) {
                                Task { await deleteEntry(entry) }
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
                .listStyle(.plain)
            }
        }
        .background(DesignSystem.Colors.background)
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

    private func sftpPassphraseSheet(challenge: SFTPPassphraseChallenge) -> some View {
        VStack(spacing: DesignSystem.Spacing.large) {
            Image(systemName: "lock.fill")
                .font(.system(size: 32))
                .foregroundStyle(DesignSystem.Colors.accent)

            Text("Key Passphrase Required")
                .font(DesignSystem.Typography.heading())

            Text("This private key is encrypted.\nEnter the passphrase to connect.")
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

    private func submitSFTPPassphrase(challenge: SFTPPassphraseChallenge) {
        guard !passphraseInput.isEmpty else { return }
        let p = passphraseInput
        passphraseInput = ""
        sftp.passphraseChallenge = nil
        Task {
            await sftp.connect(host: challenge.host, port: challenge.port,
                               username: challenge.username, pemKey: challenge.pemKey,
                               passphrase: p)
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
                // sftp.errorMessage is set by the manager
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
                // sftp.errorMessage is set by the manager
            }
        }
    }

    private func downloadEntry(_ entry: SFTPEntry) {
        Task {
            do {
                let data = try await sftp.downloadData(for: entry)
                await MainActor.run {
                    let panel = NSSavePanel()
                    panel.nameFieldStringValue = entry.filename
                    if panel.runModal() == .OK, let url = panel.url {
                        do {
                            try data.write(to: url)
                            flash("Downloaded '\(entry.filename)'.")
                        } catch {
                            // ignore write error
                        }
                    }
                }
            } catch {
                // sftp.errorMessage is set by the manager
            }
        }
    }

    private func deleteEntry(_ entry: SFTPEntry) async {
        do {
            try await sftp.delete(entry: entry)
            flash("Deleted '\(entry.filename)'.")
        } catch {
            // sftp.errorMessage is set by the manager
        }
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }
        Task {
            do {
                let data = try Data(contentsOf: url)
                try await sftp.upload(data: data, named: url.lastPathComponent)
                flash("Uploaded '\(url.lastPathComponent)'.")
            } catch {
                // sftp.errorMessage is set by the manager
            }
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
