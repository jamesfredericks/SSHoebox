import SwiftUI
import SSHoeboxCore
import UniformTypeIdentifiers

struct BackupView: View {
    let dbManager: DatabaseManager
    @StateObject private var backupManager: BackupManager
    
    @State private var showingExporter = false
    @State private var showingImporter = false
    @State private var exportData: BackupDocument?
    @State private var errorMessage: String?
    @State private var showingAlert = false
    @State private var alertMessage = ""
    
    // Simplified Backup State
    @AppStorage("backupFolder") private var backupFolder: String = "No folder selected"
    @State private var lastBackupDate = "Never"
    
    init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
        _backupManager = StateObject(wrappedValue: BackupManager(dbManager: dbManager))
    }
    
    var body: some View {
        Form {
            Section {
                Button {
                    do {
                        let data = try backupManager.createExportData()
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
    
    func restore(from url: URL) {
        guard url.startAccessingSecurityScopedResource() else {
            errorMessage = "Permission denied"
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        
        do {
            let data = try Data(contentsOf: url)
            try backupManager.restore(from: data)
            alertMessage = "Vault restored successfully. Please restart the app for changes to take effect."
            showingAlert = true
        } catch {
            errorMessage = "Restore failed: \(error.localizedDescription)"
        }
    }
    
    func performBackup() {
        Task {
            do {
                guard backupFolder != "No folder selected" else { return }
                
                let data = try backupManager.createExportData()
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
