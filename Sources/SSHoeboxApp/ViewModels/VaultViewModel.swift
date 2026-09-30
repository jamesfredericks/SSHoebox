import Foundation
import SwiftUI
import Combine
import SSHoeboxCore
import CryptoKit
import LocalAuthentication
import NIOSSH


@MainActor
class VaultViewModel: ObservableObject {
    @Published var isUnlocked: Bool = false
    @Published var isNewUser: Bool = false
    @Published var errorMessage: String?
    @Published var showBiometricSetupPrompt: Bool = false
    
    // SSH Agent
    @Published var isAgentEnabled: Bool = UserDefaults.standard.bool(forKey: "isAgentEnabled") {
        didSet {
            UserDefaults.standard.set(isAgentEnabled, forKey: "isAgentEnabled")
            if isAgentEnabled && isUnlocked {
                startAgent()
            } else if !isAgentEnabled {
                stopAgent()
            }
        }
    }
    private var agentServer: SSHAgentServer?
    
    var isBiometricAvailable: Bool { BiometricAuthManager.isBiometricAvailable() }
    var isBiometricEnrolled: Bool {
        vaultID.map { BiometricAuthManager.isBiometricEnrolled(vaultID: $0) } ?? false
    }
    var biometricTypeName: String { BiometricAuthManager.biometricTypeName() }
    var biometricSymbolName: String { BiometricAuthManager.biometricSymbolName() }
    
    var dbManager: DatabaseManager?
    var vaultKey: SymmetricKey?
    /// Identifier of the vault at the current location (nil when no metadata exists yet).
    /// Scopes per-vault state such as the Touch ID key.
    @Published private(set) var vaultID: String?
    private var idleMonitor: IdleMonitor?
    private var cancellables = Set<AnyCancellable>()

    // Rate limiting for password unlock
    private var failedUnlockAttempts: Int = 0
    private var lockoutUntil: Date?

    /// Provided by MainView so auto-lock can defer while SSH sessions are active.
    var activeSessionCount: (() -> Int)?
    
    // Path to the vault directory
    var vaultDirectoryURL: URL {
        if let savedPath = UserDefaults.standard.string(forKey: "vaultDirectoryRaw") {
            let url = URL(fileURLWithPath: savedPath)
            try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            return url
        }
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let appDir = appSupport.appendingPathComponent("com.sshoebox.app")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir
    }
    
    var dbPath: String {
        vaultDirectoryURL.appendingPathComponent("vault.db").path
    }
    
    private var metadataPath: String {
        vaultDirectoryURL.appendingPathComponent("vault_metadata.json").path
    }
    
    init() {
        checkIfVaultExists()
    }
    
    func checkIfVaultExists() {
        let dbExists = FileManager.default.fileExists(atPath: dbPath)
        let metadataExists = FileManager.default.fileExists(atPath: metadataPath)
        let keychainOK = (try? KeychainManager.read(account: "vault_metadata")) != nil
        
        // Treat as new user if there is no DB, OR if the metadata is missing from BOTH sidecar AND Keychain.
        isNewUser = !dbExists || (!metadataExists && !keychainOK)
        vaultID = (try? loadMetadata())?.identifier
    }
    
    /// Reads the vault metadata from the sidecar, falling back to the legacy Keychain copy.
    private func loadMetadata() throws -> VaultMetadata {
        try JSONDecoder().decode(VaultMetadata.self, from: currentVaultMetadata())
    }
    
    private static func isValidKey(_ key: SymmetricKey, for metadata: VaultMetadata) -> Bool {
        guard let decrypted = try? CryptoManager.decrypt(metadata.validation, using: key) else { return false }
        return String(data: decrypted, encoding: .utf8) == "SSHOEBOX_VALID"
    }
    
    /// A vault.db exists but its metadata does not (e.g. the sidecar hasn't finished syncing).
    /// Creating a vault over it would make the existing data undecryptable.
    var hasOrphanedDatabase: Bool {
        isNewUser && FileManager.default.fileExists(atPath: dbPath)
    }
    
    /// Opens the vault database with the SQLCipher key derived from the vault key,
    /// migrating a legacy plaintext database in place if needed.
    private func openDatabase(vaultKey: SymmetricKey) throws -> DatabaseManager {
        try DatabaseManager(path: dbPath, key: CryptoManager.databaseKey(from: vaultKey))
    }
    
    /// Wipes the existing vault and Keychain entry so the user can start fresh.
    func forceNewVault() {
        try? FileManager.default.removeItem(atPath: dbPath)
        try? FileManager.default.removeItem(atPath: metadataPath)
        try? KeychainManager.delete(account: "vault_metadata")
        if let vaultID { BiometricAuthManager.revokeBiometric(vaultID: vaultID) }
        self.vaultID = nil
        self.dbManager = nil
        self.vaultKey = nil
        self.isUnlocked = false
        self.isNewUser = true
        self.errorMessage = nil
    }
    
    func createVault(password: String) {
        guard !hasOrphanedDatabase else {
            self.errorMessage = "A vault database already exists in this folder but its vault_metadata.json is missing. If it is still syncing, wait and relaunch; otherwise use \"Create New Vault…\" to replace it."
            return
        }
        do {
            let salt = try CryptoManager.generateSalt()
            let key = try CryptoManager.deriveKey(password: password, salt: salt)
            
            let manager = try openDatabase(vaultKey: key)
            
            // Save metadata to portable JSON sidecar instead of Keychain
            let validationData = try CryptoManager.encrypt("SSHOEBOX_VALID".data(using: .utf8)!, using: key)
            let vaultMetadata = VaultMetadata(salt: salt, validation: validationData, version: 1)
            let metadataData = try JSONEncoder().encode(vaultMetadata)
            do {
                try metadataData.write(to: URL(fileURLWithPath: metadataPath), options: .atomic)
            } catch {
                // Without metadata the new database can never be opened; don't leave it behind.
                try? FileManager.default.removeItem(atPath: dbPath)
                throw error
            }
            
            self.dbManager = manager
            self.vaultKey = key
            self.vaultID = vaultMetadata.identifier
            self.isUnlocked = true
            self.isNewUser = false
            self.errorMessage = nil
            
            if BiometricAuthManager.isBiometricAvailable() && !BiometricAuthManager.hasVaultEnrollment(vaultID: vaultMetadata.identifier) {
                self.showBiometricSetupPrompt = true
            }
            
            // Start auto-lock monitoring
            startAutoLockMonitoring()
            
            if isAgentEnabled {
                startAgent()
            }
            
        } catch {
            self.errorMessage = "Failed to create vault: \(error.localizedDescription)"
        }
    }
    
    private func recordFailedUnlock() {
        failedUnlockAttempts += 1
        guard failedUnlockAttempts >= 5 else { return }
        // 5→30s, 6→60s, 7→120s, 8→240s, 9+→300s cap
        let delay = min(pow(2.0, Double(failedUnlockAttempts - 4)) * 15, 300)
        lockoutUntil = Date().addingTimeInterval(delay)
    }

    func unlock(password: String) {
        // Enforce lockout before attempting decryption
        if let lockout = lockoutUntil, lockout > Date() {
            let remaining = Int(lockout.timeIntervalSinceNow.rounded(.up))
            errorMessage = "Too many failed attempts. Try again in \(remaining)s."
            return
        }

        do {
            // 1. Retrieve Salt & Validation from Sidecar (or fallback to Keychain)
            let metadataData: Data
            if FileManager.default.fileExists(atPath: metadataPath) {
                // Portable Vault Sidecar
                metadataData = try Data(contentsOf: URL(fileURLWithPath: metadataPath))
            } else {
                // Legacy Keychain Migration
                metadataData = try KeychainManager.read(account: "vault_metadata")
                try metadataData.write(to: URL(fileURLWithPath: metadataPath))
            }
            
            let metadata = try JSONDecoder().decode(VaultMetadata.self, from: metadataData)
            
            // 2. Derive Key
            let key = try CryptoManager.deriveKey(password: password, salt: metadata.salt)
            
            // 3. Verify Key
            let decryptedValidation = try CryptoManager.decrypt(metadata.validation, using: key)
            guard let validationString = String(data: decryptedValidation, encoding: .utf8),
                  validationString == "SSHOEBOX_VALID" else {
                recordFailedUnlock()
                if let lockout = lockoutUntil, lockout > Date() {
                    let remaining = Int(lockout.timeIntervalSinceNow.rounded(.up))
                    self.errorMessage = "Too many failed attempts. Try again in \(remaining)s."
                } else {
                    self.errorMessage = "Invalid password."
                }
                return
            }

            // 4. Open DB
            failedUnlockAttempts = 0
            lockoutUntil = nil
            let manager = try openDatabase(vaultKey: key)
            self.dbManager = manager
            self.vaultKey = key
            
            // 5. Check Migration
            if (metadata.version ?? 0) < 1 {
                try performMetadataEncryption(db: manager, key: key)
                var newMetadata = metadata
                newMetadata.version = 1
                let newMetadataData = try JSONEncoder().encode(newMetadata)
                try newMetadataData.write(to: URL(fileURLWithPath: metadataPath))
            }
            
            self.isUnlocked = true
            self.errorMessage = nil
            
            // Prompt biometric enrollment if this vault has no Touch ID key of its own yet
            self.vaultID = metadata.identifier
            if BiometricAuthManager.isBiometricAvailable() && !BiometricAuthManager.hasVaultEnrollment(vaultID: metadata.identifier) {
                self.showBiometricSetupPrompt = true
            }
            
            // Start auto-lock monitoring
            // Start auto-lock monitoring
            startAutoLockMonitoring()
            
            // Start agent if enabled
            if isAgentEnabled {
                startAgent()
            }
            
        } catch {
            self.errorMessage = "Unlock failed: \(error.localizedDescription)"
        }
    }
    
    /// Unlock the vault using Touch ID / Face ID.
    func unlockWithBiometrics() {
        Task {
            do {
                let metadata = try loadMetadata()
                let vaultID = metadata.identifier
                let usingLegacyKey = !BiometricAuthManager.hasVaultEnrollment(vaultID: vaultID)
                let key = try await BiometricAuthManager.unlockWithBiometrics(vaultID: vaultID)
                
                // Validate the key against the stored validation token
                guard Self.isValidKey(key, for: metadata) else {
                    self.errorMessage = usingLegacyKey
                        ? "\(biometricTypeName) was set up for a different vault. Unlock with your password, then enable \(biometricTypeName) for this vault."
                        : "Biometric unlock failed: key mismatch."
                    return
                }
                
                // The legacy shared key belongs to this vault: move it to a per-vault item.
                if usingLegacyKey {
                    try? BiometricAuthManager.enrollBiometric(vaultKey: key, vaultID: vaultID)
                }
                
                let manager = try openDatabase(vaultKey: key)
                self.dbManager = manager
                self.vaultKey = key
                self.vaultID = vaultID
                self.isUnlocked = true
                self.errorMessage = nil
                startAutoLockMonitoring()
                
                // Start agent if enabled
                if self.isAgentEnabled {
                    self.startAgent()
                }
                
            } catch {
                self.errorMessage = "Biometric unlock failed: \(error.localizedDescription)"
            }
        }
    }
    
    /// Enroll biometrics using the currently unlocked vault key.
    func enrollBiometrics() {
        guard let key = vaultKey, let vaultID else { return }
        do {
            try BiometricAuthManager.enrollBiometric(vaultKey: key, vaultID: vaultID)
            self.showBiometricSetupPrompt = false
            self.errorMessage = nil
        } catch {
            // Keep the setup prompt open and surface the error to the user
            self.errorMessage = "Failed to enable biometric unlock: \(error.localizedDescription)"
        }
    }
    
    /// Disable biometric unlock and remove the stored key.
    func disableBiometrics() {
        guard let vaultID else { return }
        BiometricAuthManager.revokeBiometric(vaultID: vaultID)
    }
    
    private func performMetadataEncryption(db: DatabaseManager, key: SymmetricKey) throws {
        try db.dbWriter.write { db in
            // Migrate Hosts
            let hosts = try SavedHost.fetchAll(db)
            for var host in hosts {
                // Check if already base64 (crude check, but if migration runs once, we assume plaintext)
                // Actually, since we check version < 1, we assume all are plaintext.
                host.name = try CryptoManager.encryptString(host.name, using: key)
                host.hostname = try CryptoManager.encryptString(host.hostname, using: key)
                host.user = try CryptoManager.encryptString(host.user, using: key)
                try host.update(db)
            }
            
            // Migrate Credentials
            let credentials = try Credential.fetchAll(db)
            for var cred in credentials {
                cred.username = try CryptoManager.encryptString(cred.username, using: key)
                try cred.update(db)
            }
        }
    }
    
    func lock() {
        self.isUnlocked = false
        self.vaultKey = nil
        self.dbManager = nil
        
        // Stop auto-lock monitoring
        stopAutoLockMonitoring()
        
        // Stop agent
        stopAgent()
    }
    
    // MARK: - Auto-Lock
    
    private func startAutoLockMonitoring() {
        // Get timeout from UserDefaults (in minutes, 0 = disabled)
        let timeoutMinutes = UserDefaults.standard.integer(forKey: "autoLockTimeout")
        let timeoutInterval: TimeInterval
        
        if timeoutMinutes == 0 {
            // First launch or "Never" selected - default to 15 minutes
            if !UserDefaults.standard.bool(forKey: "hasSetAutoLockTimeout") {
                timeoutInterval = 15 * 60 // 15 minutes default
                UserDefaults.standard.set(15, forKey: "autoLockTimeout")
                UserDefaults.standard.set(true, forKey: "hasSetAutoLockTimeout")
            } else {
                // User explicitly chose "Never"
                timeoutInterval = 0
            }
        } else {
            timeoutInterval = TimeInterval(timeoutMinutes * 60)
        }
        
        // Create and start idle monitor
        let monitor = IdleMonitor(timeoutInterval: timeoutInterval)
        self.idleMonitor = monitor
        
        // Subscribe to idle events
        monitor.$isIdle
            .sink { [weak self] isIdle in
                guard isIdle else { return }
                // Defer auto-lock while SSH sessions are actively connected
                if (self?.activeSessionCount?() ?? 0) > 0 {
                    self?.idleMonitor?.resetActivity()
                    return
                }
                self?.lock()
            }
            .store(in: &cancellables)
        
        // Listen for timeout preference changes
        NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)
            .sink { [weak self] _ in
                self?.restartAutoLockMonitoring()
            }
            .store(in: &cancellables)
        
        monitor.startMonitoring()
    }
    
    func restartAutoLockMonitoring() {
        guard isUnlocked else { return }
        stopAutoLockMonitoring()
        startAutoLockMonitoring()
    }
    
    private func stopAutoLockMonitoring() {
        idleMonitor?.stopMonitoring()
        idleMonitor = nil
        cancellables.removeAll()
    }
    
    func getDependencies() -> (DatabaseManager, SymmetricKey)? {
        guard let db = dbManager, let key = vaultKey else { return nil }
        return (db, key)
    }
    
    func resetApp() {
        // Delete DB and Sidecar
        try? FileManager.default.removeItem(atPath: dbPath)
        try? FileManager.default.removeItem(atPath: metadataPath)
        
        // Delete Keychain Item (legacy)
        try? KeychainManager.delete(account: "vault_metadata")
        
        self.lock()
        self.checkIfVaultExists()
        self.errorMessage = nil
    }
    
    // MARK: - Portable Vault Management
    
    func moveVault(to url: URL) throws {
        let source = vaultDirectoryURL.standardizedFileURL.resolvingSymlinksInPath()
        let destination = url.standardizedFileURL.resolvingSymlinksInPath()
        guard source != destination else { return }
        
        let fm = FileManager.default
        try fm.createDirectory(at: destination, withIntermediateDirectories: true)
        
        let fileNames = ["vault.db", "vault_metadata.json"]
        for name in fileNames where fm.fileExists(atPath: destination.appendingPathComponent(name).path) {
            throw VaultError.destinationHasVault
        }
        
        self.lock()
        
        // Copy everything first; only delete the originals once every copy has succeeded.
        let filesToMove = (fileNames + ["vault.db-journal", "vault.db-wal", "vault.db-shm"])
            .filter { fm.fileExists(atPath: source.appendingPathComponent($0).path) }
        var copied: [URL] = []
        do {
            for name in filesToMove {
                let target = destination.appendingPathComponent(name)
                try fm.copyItem(at: source.appendingPathComponent(name), to: target)
                copied.append(target)
            }
        } catch {
            copied.forEach { try? fm.removeItem(at: $0) }
            throw error
        }
        
        UserDefaults.standard.set(destination.path, forKey: "vaultDirectoryRaw")
        for name in filesToMove {
            try? fm.removeItem(at: source.appendingPathComponent(name))
        }
        checkIfVaultExists()
    }
    
    func openExistingVault(at url: URL) {
        self.lock()
        UserDefaults.standard.set(url.path, forKey: "vaultDirectoryRaw")
        checkIfVaultExists()
    }
    
    // MARK: - Backup
    
    /// Current `vault_metadata.json` contents, falling back to the legacy Keychain copy.
    func currentVaultMetadata() throws -> Data {
        if FileManager.default.fileExists(atPath: metadataPath) {
            return try Data(contentsOf: URL(fileURLWithPath: metadataPath))
        }
        return try KeychainManager.read(account: "vault_metadata")
    }
    
    /// Validates a backup, locks the vault, and replaces the database and metadata with it.
    /// The user must unlock again with the password that was in use when the backup was made.
    func restoreBackup(_ data: Data) throws {
        let backup = try BackupManager.verify(data)
        
        lock()
        try BackupManager.install(backup, databasePath: dbPath, metadataPath: metadataPath)
        // Touch ID keys are per vault, so a restored vault with different metadata simply
        // has no enrollment until the user enables it again.
        checkIfVaultExists()
    }
    
    // MARK: - SSH Agent Management
    
    func startAgent() {
        guard isAgentEnabled, let socketPath = agentSocketPath else { return }
        print("Starting SSH Agent at \(socketPath)")
        
        // Ensure only one instance
        stopAgent()
        
        agentServer = SSHAgentServer(socketPath: socketPath, delegate: self)
        Task {
            do {
                try await agentServer?.start()
            } catch {
                await MainActor.run {
                    self.errorMessage = "Failed to start SSH Agent: \(error.localizedDescription)"
                }
            }
        }
    }
    
    func stopAgent() {
        if let server = agentServer {
            Task {
                try? await server.stop()
            }
            agentServer = nil
        }
    }
    
    var agentSocketPath: String? {
        guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let appDir = appSupport.appendingPathComponent("com.sshoebox.app")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("agent.sock").path
    }
}

enum VaultError: LocalizedError {
    case destinationHasVault
    
    var errorDescription: String? {
        switch self {
        case .destinationHasVault:
            return "The selected folder already contains a vault. Use \"Open Existing Vault…\" to switch to it, or choose an empty folder."
        }
    }
}
