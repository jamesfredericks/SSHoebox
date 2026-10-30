import SwiftUI
import SSHoeboxCore

/// Preferences section for syncing the vault between Macs.
struct SyncSettingsSection: View {
    @ObservedObject var viewModel: VaultViewModel
    @ObservedObject var sync: SyncController

    var body: some View {
        Section {
            if let folder = sync.folderURL {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Sync Folder")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)

                    HStack {
                        Text(folder.path)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)

                        Spacer()

                        Button {
                            NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: folder.path)
                        } label: {
                            Image(systemName: "folder")
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                        .help("Show in Finder")
                    }
                    .padding(8)
                    .background(DesignSystem.Colors.surface)
                    .cornerRadius(6)

                    status

                    HStack(spacing: 12) {
                        Button("Sync Now") { sync.syncNow() }
                            .buttonStyle(.bordered)
                            .disabled(sync.isSyncing)
                        Button("Stop Syncing") { sync.setFolder(nil) }
                            .buttonStyle(.bordered)
                    }
                    .padding(.top, 4)
                }
            } else {
                Button("Choose Sync Folder...") { chooseFolder() }
                    .buttonStyle(.bordered)
            }
        } header: {
            Text("Sync")
                .foregroundStyle(DesignSystem.Colors.textSecondary)
        } footer: {
            Text("Keeps hosts, credentials, trusted host keys and preferences the same on all your Macs. Choose a folder in iCloud Drive, Dropbox or OneDrive; each Mac keeps an encrypted copy of the vault there that only your master password opens. On another Mac, choose \"Join a Synced Vault...\" instead of creating a vault. The vault location, backup folder and Touch ID stay separate on each Mac.")
                .foregroundStyle(DesignSystem.Colors.textSecondary)
        }
    }

    @ViewBuilder
    private var status: some View {
        VStack(alignment: .leading, spacing: 4) {
            if sync.isSyncing {
                Label("Syncing...", systemImage: "arrow.triangle.2.circlepath")
            } else if let lastSyncedAt = sync.lastSyncedAt {
                Label("Last synced at \(lastSyncedAt.formatted(date: .omitted, time: .shortened))", systemImage: "checkmark.circle")
            }
            if let error = sync.lastError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            ForEach(sync.otherDevices) { device in
                Label("\(device.name): synced \(device.lastSyncedAt.formatted(date: .abbreviated, time: .shortened))", systemImage: "laptopcomputer")
            }
        }
        .font(.caption)
        .foregroundStyle(DesignSystem.Colors.textSecondary)
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.prompt = "Sync Here"
        panel.message = "Choose a folder in iCloud Drive, Dropbox or OneDrive. On your other Macs, choose the same folder."

        if panel.runModal() == .OK, let url = panel.url {
            do {
                try viewModel.startSyncing(at: url)
            } catch {
                viewModel.errorMessage = "Couldn't start syncing: \(error.localizedDescription)"
            }
        }
    }
}
