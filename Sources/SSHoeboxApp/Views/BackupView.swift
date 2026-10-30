import SwiftUI
import SSHoeboxCore
import UniformTypeIdentifiers

struct BackupView: View {
    let dbManager: DatabaseManager
    @StateObject private var backupManager: BackupManager
    @ObservedObject var vaultViewModel: VaultViewModel
    
    @State private var showingExporter = false
    @State private var showingImporter = false
    @State private var exportData: BackupDocument?
    @State private var errorMessage: String?
    @State private var showingAlert = false
    @State private var alertMessage = ""
    
    // Restore: a checked backup waiting for its vault's password and/or the user's confirmation
    @State private var pendingRestore: VaultViewModel.PendingRestore?
    @State private var showingRestorePassword = false
    @State private var showingRestoreConfirm = false
    @State private var restorePassword = ""
    @State private var restorePasswordError: String?
    @State private var isCheckingRestore = false
    
    // Simplified Backup State
    @AppStorage("backupFolder") private var backupFolder: String = "No folder selected"
    @State private var lastBackupDate = "Never"
    
    init(dbManager: DatabaseManager, vaultViewModel: VaultViewModel) {
        self.dbManager = dbManager
        self.vaultViewModel = vaultViewModel
        _backupManager = StateObject(wrappedValue: BackupManager(dbManager: dbManager))
    }
    
    var body: some View {
        Form {
            Section {
                Button {
                    do {
                        let data = try makeExportData()
                        exportData = BackupDocument(data: data)
                        showingExporter = true
                    } catch {
                        errorMessage = "Export failed: \(error.localizedDescription)"
                    }
                } label: {
                    Label("Export Single File", systemImage: "square.and.arrow.up")
                }
                
                Button {
                    showingImporter = true
                } label: {
                    Label("Import Backup File", systemImage: "square.and.arrow.down")
                }
            } header: {
                Text("File Operations")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            Section {
                HStack {
                    VStack(alignment: .leading) {
                        Text("Destination Folder")
                            .font(DesignSystem.Typography.body())
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                        Text(backupFolder)
                            .font(.caption)
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer()
                    Button("Select Folder") {
                        selectFolder()
                    }
                }
                
                Button("Backup Now") {
                    performBackup()
                }
                .disabled(backupFolder == "No folder selected")
                
                if lastBackupDate != "Never" {
                    Text("Last Backup: \(lastBackupDate)")
                        .font(.caption)
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
                
                Text("Select a folder (e.g., in your Documents or iCloud Drive) to store backups.")
                    .font(.caption)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            } header: {
                Text("Automated Backup Location")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            if let error = errorMessage {
                Section {
                    Text(error)
                        .foregroundStyle(DesignSystem.Colors.error)
                }
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(DesignSystem.Colors.background)
        .tint(DesignSystem.Colors.accent)
        .navigationTitle("Backups")
        .fileExporter(isPresented: $showingExporter, document: exportData, contentType: .json, defaultFilename: "SSHoebox_Backup") { result in
            switch result {
            case .success(let url):
                print("Saved to \(url)")
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
        .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.json]) { result in
            switch result {
            case .success(let url):
                restore(from: url)
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
        .sheet(isPresented: $showingRestorePassword, onDismiss: { restorePassword = "" }) {
            restorePasswordSheet
        }
        .alert("Restore This Backup?", isPresented: $showingRestoreConfirm, presenting: pendingRestore) { pending in
            Button("Cancel", role: .cancel) { pendingRestore = nil }
            Button("Restore", role: .destructive) { performRestore(pending) }
        } message: { pending in
            Text(restoreConfirmMessage(for: pending))
        }
        .alert("Backup Status", isPresented: $showingAlert) {
            Button("OK") {}
        } message: {
            Text(alertMessage)
                .foregroundStyle(DesignSystem.Colors.textPrimary)
        }
    }
    
    func selectFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Select Backup Folder"
        
        if panel.runModal() == .OK {
            backupFolder = panel.url?.path ?? "Error selecting folder"
        }
    }
    
    private func makeExportData() throws -> Data {
        guard let vaultKey = vaultViewModel.vaultKey else { throw BackupError.notAuthentic }
        return try backupManager.createExportData(vaultMetadata: vaultViewModel.currentVaultMetadata(), vaultKey: vaultKey)
    }
    
    func restore(from url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        
        do {
            let data = try Data(contentsOf: url)
            let pending = try vaultViewModel.prepareRestore(data)
            pendingRestore = pending
            errorMessage = nil
            if pending.needsPassword {
                restorePasswordError = nil
                showingRestorePassword = true
            } else {
                Task {
                    do {
                        try await vaultViewModel.authenticateRestore(pending)
                        showingRestoreConfirm = true
                    } catch {
                        pendingRestore = nil
                        errorMessage = "Restore failed: \(error.localizedDescription)"
                    }
                }
            }
        } catch {
            errorMessage = "Restore failed: \(error.localizedDescription)"
        }
    }
    
    private func checkRestorePassword() {
        guard let pending = pendingRestore, !restorePassword.isEmpty, !isCheckingRestore else { return }
        isCheckingRestore = true
        let password = restorePassword
        Task {
            defer { isCheckingRestore = false }
            do {
                try await vaultViewModel.authenticateRestore(pending, password: password)
                showingRestorePassword = false
                showingRestoreConfirm = true
            } catch {
                restorePasswordError = error.localizedDescription
            }
        }
    }
    
    private func performRestore(_ pending: VaultViewModel.PendingRestore) {
        pendingRestore = nil
        // restoreBackup locks the vault (dismissing this view), so later errors are
        // reported on the unlock screen. The user then unlocks with the backup's password.
        do {
            try vaultViewModel.restoreBackup(pending)
        } catch {
            vaultViewModel.errorMessage = "Restore failed: \(error.localizedDescription)"
        }
    }
    
    private func restoreConfirmMessage(for pending: VaultViewModel.PendingRestore) -> String {
        let date = pending.backup.timestamp.formatted(date: .abbreviated, time: .shortened)
        var message = "This replaces every host and credential in the current vault with the backup from \(date). Anything added since will be lost. The vault locks, and you then unlock it with the password that was in use when the backup was made."
        if vaultViewModel.sync.isEnabled {
            message += "\n\nSync is on, so the backup also replaces the vault on your other Macs when they next sync."
        }
        if pending.isUnauthenticated {
            message += "\n\nThis backup was made by an older version of SSHoebox, so it can't be checked for tampering. Only restore it if you're sure where it came from."
        }
        return message
    }
    
    private var restorePasswordSheet: some View {
        VStack(spacing: 16) {
            Text("Backup From Another Vault")
                .font(.headline)
            Text("This backup belongs to a different vault. Enter that vault's master password so the backup can be checked before it replaces this one.")
                .font(.callout)
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .multilineTextAlignment(.center)
            SecureField("Backup's Master Password", text: $restorePassword)
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)
                .onSubmit { checkRestorePassword() }
            if let restorePasswordError {
                Text(restorePasswordError)
                    .font(.caption)
                    .foregroundStyle(DesignSystem.Colors.error)
            }
            HStack {
                Button("Cancel") {
                    pendingRestore = nil
                    showingRestorePassword = false
                }
                .keyboardShortcut(.cancelAction)
                Button {
                    checkRestorePassword()
                } label: {
                    if isCheckingRestore { ProgressView().controlSize(.small) } else { Text("Continue") }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(restorePassword.isEmpty || isCheckingRestore)
            }
        }
        .padding(24)
        .frame(width: 400)
    }
    
    func performBackup() {
        Task {
            do {
                guard backupFolder != "No folder selected" else { return }
                
                let data = try makeExportData()
                let folder = backupFolder // Capture for detached task
                
                // OFF-LOAD: Move direct file operations to a detached task
                try await Task.detached(priority: .background) {
                    let folderURL = URL(fileURLWithPath: folder)
                    
                    // Verify folder existence
                    var isDirectory: ObjCBool = false
                    guard FileManager.default.fileExists(atPath: folder, isDirectory: &isDirectory), isDirectory.boolValue else {
                        throw NSError(domain: "BackupError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Selected folder does not exist or is invalid."])
                    }
                    
                    let filename = "SSHoebox_Backup_\(Int(Date().timeIntervalSince1970)).json"
                    let fileURL = folderURL.appendingPathComponent(filename)
                    
                    try data.write(to: fileURL)
                    
                    await MainActor.run {
                        let timestamp = Date().formatted(date: .abbreviated, time: .shortened)
                        // Trigger UI update back on main thread
                        self.onBackupComplete(timestamp: timestamp, filename: fileURL.lastPathComponent)
                    }
                }.value
            } catch {
                await MainActor.run {
                    errorMessage = "Backup failed: \(error.localizedDescription)"
                }
            }
        }
    }
    
    @MainActor
    private func onBackupComplete(timestamp: String, filename: String) {
        lastBackupDate = timestamp
        alertMessage = "Backup saved successfully to \(filename)"
        showingAlert = true
        errorMessage = nil
    }
}

struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    
    var data: Data
    
    init(data: Data) {
        self.data = data
    }
    
    init(configuration: ReadConfiguration) throws {
        if let data = configuration.file.regularFileContents {
            self.data = data
        } else {
            throw CocoaError(.fileReadCorruptFile)
        }
    }
    
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        return FileWrapper(regularFileWithContents: data)
    }
}
