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
    /// True while the master password is being checked (key derivation takes a moment).
    @Published private(set) var isUnlocking: Bool = false
    
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
    
    /// Keeps the vault and settings the same on the user's other Macs.
    let sync = SyncController()
    
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

    /// Provided by SSHoeboxApp to end terminal sessions, which hold their own copy of the vault key.
    var onLock: (() -> Void)?
    
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
        sync.applySettings = { [weak self] in self?.applySyncedSettings($0) }
        checkIfVaultExists()
    }
    
    func checkIfVaultExists() {
        let dbExists = FileManager.default.fileExists(atPath: dbPath)
        let metadataExists = FileManager.default.fileExists(atPath: metadataPath)
        let keychainOK = (try? KeychainManager.read(account: "vault_metadata")) != nil
        // Joined a synced vault: the database is created and filled on first unlock.
        let joinedSyncedVault = !dbExists && metadataExists && sync.isEnabled
        
        // Treat as new user if there is no DB, OR if the metadata is missing from BOTH sidecar AND Keychain.
        isNewUser = !(dbExists || joinedSyncedVault) || (!metadataExists && !keychainOK)
        vaultID = (try? loadMetadata())?.identifier
    }
    
    /// Reads the vault metadata from the sidecar, falling back to the legacy Keychain copy.
    private func loadMetadata() throws -> VaultMetadata {
        try JSONDecoder().decode(VaultMetadata.self, from: currentVaultMetadata())
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
        // The sync folder holds the old vault.
        sync.setFolder(nil)
        self.vaultID = nil
        self.dbManager = nil
        self.vaultKey = nil
        self.isUnlocked = false
        self.isNewUser = true
        self.errorMessage = nil
    }
    
    /// Minimum length for a new master password. It protects the vault against offline
    /// guessing by anyone who obtains a copy of the vault files.
    static let minimumPasswordLength = 12

    func createVault(password: String) {
        guard !hasOrphanedDatabase else {
            self.errorMessage = "A vault database already exists in this folder but its vault_metadata.json is missing. If it is still syncing, wait and relaunch; otherwise use \"Create New Vault…\" to replace it."
            return
        }
        guard password.count >= Self.minimumPasswordLength else {
            self.errorMessage = "Use a master password of at least \(Self.minimumPasswordLength) characters."
            return
        }
        guard !isUnlocking else { return }
        isUnlocking = true
        Task {
            defer { isUnlocking = false }
            do {
                // Key wrapping runs the (deliberately slow) KDF, so keep it off the main thread.
                let (metadata, key) = try await Task.detached(priority: .userInitiated) {
                    try VaultMetadata.create(password: password)
                }.value
                
                let manager = try openDatabase(vaultKey: key)
                try FieldEncryptionMigration.run(manager, vaultKey: key)
                
                // Save metadata to portable JSON sidecar instead of Keychain
                do {
                    try writeMetadata(metadata)
                } catch {
                    // Without metadata the new database can never be opened; don't leave it behind.
                    try? FileManager.default.removeItem(atPath: dbPath)
                    throw error
                }
                
                completeUnlock(dbManager: manager, vaultKey: key, vaultID: metadata.identifier)
            } catch {
                self.errorMessage = "Failed to create vault: \(error.localizedDescription)"
            }
        }
    }
    
    private func writeMetadata(_ metadata: VaultMetadata) throws {
        try JSONEncoder().encode(metadata).write(to: URL(fileURLWithPath: metadataPath), options: .atomic)
    }
    
    /// Shared tail of every successful unlock: publish the unlocked state and start the
    /// services that run while the vault is open.
    private func completeUnlock(dbManager manager: DatabaseManager, vaultKey key: SymmetricKey, vaultID: String) {
        self.dbManager = manager
        self.vaultKey = key
        self.vaultID = vaultID
        self.isUnlocked = true
        self.isNewUser = false
        self.errorMessage = nil
        
        // Prompt biometric enrollment if this vault has no Touch ID key of its own yet
        if BiometricAuthManager.isBiometricAvailable() && !BiometricAuthManager.hasVaultEnrollment(vaultID: vaultID) {
            self.showBiometricSetupPrompt = true
        }
        
        startAutoLockMonitoring()
        
        if isAgentEnabled {
            startAgent()
        }
        
        if let metadata = try? currentVaultMetadata() {
            sync.start(dbManager: manager, vaultKey: key, vaultMetadata: metadata)
        }
    }
    
    /// Opens the database and brings older vault data up to the current field encryption format.
    private func openAndMigrate(vaultKey key: SymmetricKey) throws -> DatabaseManager {
        let manager = try openDatabase(vaultKey: key)
        if try FieldEncryptionMigration.isNeeded(manager) {
            try FieldEncryptionMigration.run(manager, vaultKey: key)
        }
        return manager
    }
    
    private func recordFailedUnlock() {
        failedUnlockAttempts += 1
        guard failedUnlockAttempts >= 5 else { return }
        // 5→30s, 6→60s, 7→120s, 8→240s, 9+→300s cap
        let delay = min(pow(2.0, Double(failedUnlockAttempts - 4)) * 15, 300)
        lockoutUntil = Date().addingTimeInterval(delay)
    }
    
    private var lockoutMessage: String? {
        guard let lockout = lockoutUntil, lockout > Date() else { return nil }
        let remaining = Int(lockout.timeIntervalSinceNow.rounded(.up))
        return "Too many failed attempts. Try again in \(remaining)s."
    }

    func unlock(password: String) {
        // Enforce lockout before attempting decryption
        if let lockoutMessage {
            errorMessage = lockoutMessage
            return
        }
        guard !isUnlocking else { return }
        isUnlocking = true
        
        Task {
            defer { isUnlocking = false }
            do {
                // 1. Retrieve the metadata from the sidecar (or migrate the legacy Keychain copy)
                let metadataData: Data
                if FileManager.default.fileExists(atPath: metadataPath) {
                    metadataData = try Data(contentsOf: URL(fileURLWithPath: metadataPath))
                } else {
                    metadataData = try KeychainManager.read(account: "vault_metadata")
                    try metadataData.write(to: URL(fileURLWithPath: metadataPath), options: .atomic)
                }
                let metadata = try JSONDecoder().decode(VaultMetadata.self, from: metadataData)
                
                // 2. Derive and check the key off the main thread. A wrong password must count
                // as a failed attempt rather than escaping to the generic catch below.
                let derived = try await Task.detached(priority: .userInitiated) {
                    try metadata.vaultKey(password: password)
                }.value
                guard let key = derived else {
                    recordFailedUnlock()
                    self.errorMessage = lockoutMessage ?? "Invalid password."
                    return
                }
                failedUnlockAttempts = 0
                lockoutUntil = nil
                
                // 3. Open the DB, migrating older field encryption
                let manager = try openAndMigrate(vaultKey: key)
                
                // 4. Upgrade legacy metadata to a wrapped key with the current KDF settings.
                // Best effort: the vault is already open, and the upgrade is retried next time.
                if metadata.needsUpgrade {
                    do {
                        let upgraded = try await Task.detached(priority: .userInitiated) {
                            try metadata.rewrapped(vaultKey: key, password: password)
                        }.value
                        try writeMetadata(upgraded)
                    } catch {
                        print("Vault metadata upgrade failed: \(error)")
                    }
                }
                
                completeUnlock(dbManager: manager, vaultKey: key, vaultID: metadata.identifier)
            } catch {
                self.errorMessage = "Unlock failed: \(error.localizedDescription)"
            }
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
                guard metadata.isValid(key) else {
                    self.errorMessage = usingLegacyKey
                        ? "\(biometricTypeName) was set up for a different vault. Unlock with your password, then enable \(biometricTypeName) for this vault."
                        : "Biometric unlock failed: key mismatch."
                    return
                }
                
                // The legacy shared key belongs to this vault: move it to a per-vault item.
                if usingLegacyKey {
                    try? BiometricAuthManager.enrollBiometric(vaultKey: key, vaultID: vaultID)
                }
                
                let manager = try openAndMigrate(vaultKey: key)
                completeUnlock(dbManager: manager, vaultKey: key, vaultID: vaultID)

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
    
    func lock() {
        self.isUnlocked = false
        self.vaultKey = nil
        self.dbManager = nil

        // End SSH sessions and clear any secret still on the clipboard
        onLock?()
        ClipboardManager.shared.clearNow()
        
        // Stop auto-lock monitoring
        stopAutoLockMonitoring()
        
        // Stop agent
        stopAgent()
        
        sync.stop()
    }
    
    // MARK: - Auto-Lock
    
    /// UserDefaults key: keep the vault unlocked while terminal sessions are connected.
    /// Off by default, so an unattended Mac still locks (which also ends the sessions).
    static let deferAutoLockForSessionsKey = "autoLockDeferForSessions"
    
    /// The auto-lock timeout from Preferences in seconds (0 = never).
    private var autoLockTimeoutInterval: TimeInterval {
        // Unset means first launch: default to 15 minutes. A stored 0 is an explicit "Never".
        if !UserDefaults.standard.bool(forKey: "hasSetAutoLockTimeout") {
            if UserDefaults.standard.integer(forKey: "autoLockTimeout") == 0 {
                UserDefaults.standard.set(15, forKey: "autoLockTimeout")
            }
            UserDefaults.standard.set(true, forKey: "hasSetAutoLockTimeout")
        }
        return TimeInterval(UserDefaults.standard.integer(forKey: "autoLockTimeout") * 60)
    }
    
    private func startAutoLockMonitoring() {
        let monitor = IdleMonitor(timeoutInterval: autoLockTimeoutInterval)
        self.idleMonitor = monitor
        
        // Subscribe to idle events
        monitor.$isIdle
            .sink { [weak self] isIdle in
                guard let self, isIdle else { return }
                if UserDefaults.standard.bool(forKey: Self.deferAutoLockForSessionsKey),
                   (self.activeSessionCount?() ?? 0) > 0 {
                    self.idleMonitor?.resetActivity()
                    return
                }
                self.lock()
            }
            .store(in: &cancellables)
        
        monitor.startMonitoring()
    }
    
    /// Applies a changed auto-lock timeout to the running monitor without resetting the idle
    /// clock. (Monitoring used to restart on every UserDefaults write, including window
    /// autosave, so the idle clock kept being reset and auto-lock rarely fired.)
    func autoLockTimeoutDidChange() {
        idleMonitor?.timeoutInterval = autoLockTimeoutInterval
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
        sync.setFolder(nil)
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
    
    // MARK: - Sync
    
    /// Starts syncing the open vault through a folder in iCloud Drive, Dropbox or the like.
    func startSyncing(at folder: URL) throws {
        try sync.enable(folder, vaultDirectory: vaultDirectoryURL)
    }
    
    /// Sets up this Mac, which has no vault yet, to use the vault another Mac syncs through
    /// `folder`. The vault's data arrives once it's unlocked with its master password.
    func joinSyncedVault(at folder: URL) throws {
        guard !FileManager.default.fileExists(atPath: dbPath) else { throw SyncSetupError.vaultExists }
        let resolved = try VaultSyncEngine.resolveFolder(folder)
        guard let synced = try VaultSyncEngine.vaultMetadata(in: resolved) else { throw SyncSetupError.notASyncFolder }
        try synced.data.write(to: URL(fileURLWithPath: metadataPath), options: .atomic)
        sync.setFolder(resolved)
        checkIfVaultExists()
        errorMessage = nil
    }
    
    /// Applies settings changed on another Mac, including the side effects the Preferences
    /// controls would have had.
    private func applySyncedSettings(_ values: [String: SyncedValue]) {
        for (key, value) in values where key != "isAgentEnabled" {
            SyncedSettings.store(value, forKey: key)
        }
        if values["autoLockTimeout"] != nil {
            UserDefaults.standard.set(true, forKey: "hasSetAutoLockTimeout")
            autoLockTimeoutDidChange()
        }
        if values["clipboardClearTimeout"] != nil {
            ClipboardManager.shared.clipboardClearTimeout = ClipboardManager.savedClearTimeout
        }
        if case .bool(let enabled)? = values["isAgentEnabled"], enabled != isAgentEnabled {
            isAgentEnabled = enabled // starts or stops the agent
        }
        if values["selectedThemeId"] != nil || values["terminalFontSize"] != nil {
            ThemeManager.shared.reloadFromDefaults()
        }
        NotificationCenter.default.post(name: .syncedSettingsDidChange, object: nil)
    }
    
    // MARK: - Backup
    
    /// Current `vault_metadata.json` contents, falling back to the legacy Keychain copy.
    func currentVaultMetadata() throws -> Data {
        if FileManager.default.fileExists(atPath: metadataPath) {
            return try Data(contentsOf: URL(fileURLWithPath: metadataPath))
        }
        return try KeychainManager.read(account: "vault_metadata")
    }
    
    /// A backup that has been checked and is waiting for the user to confirm the restore.
    struct PendingRestore {
        let backup: VaultBackup
        /// The backup is from another vault, so its master password is needed to check it.
        let needsPassword: Bool
        /// Made before backups were authenticated (v4); only its checksum could be checked.
        var isUnauthenticated: Bool { backup.authenticationCode == nil }
    }

    /// Checks a backup's structure and works out how its authenticity can be checked.
    func prepareRestore(_ data: Data) throws -> PendingRestore {
        let backup = try BackupManager.verify(data)
        let fromThisVault = backup.metadata.map { $0.identifier == vaultID } ?? true
        return PendingRestore(backup: backup, needsPassword: !fromThisVault)
    }

    /// Authenticates a pending restore with the open vault's key, or with `password` for a
    /// backup of another vault. Throws if the backup was altered or the password is wrong.
    func authenticateRestore(_ pending: PendingRestore, password: String? = nil) async throws {
        let key: SymmetricKey
        if pending.needsPassword {
            guard let password, let metadata = pending.backup.metadata else { throw BackupError.notAuthentic }
            let derived = try await Task.detached(priority: .userInitiated) {
                try metadata.vaultKey(password: password)
            }.value
            guard let derived else { throw RestoreError.wrongPassword }
            key = derived
        } else {
            guard let vaultKey else { throw BackupError.notAuthentic }
            key = vaultKey
        }
        if pending.isUnauthenticated {
            // Nothing to check beyond the checksum, but the backup's metadata must belong to
            // the key, or the restored vault couldn't be unlocked.
            if let metadata = pending.backup.metadata, !metadata.isValid(key) { throw BackupError.notAuthentic }
        } else if !pending.backup.isAuthentic(using: key) {
            throw BackupError.notAuthentic
        }
    }

    /// Locks the vault and replaces the database and metadata with an authenticated backup.
    /// The user must unlock again with the password that was in use when the backup was made.
    func restoreBackup(_ pending: PendingRestore) throws {
        lock()
        try BackupManager.install(pending.backup, databasePath: dbPath, metadataPath: metadataPath)
        // Otherwise the next sync would merge the other Macs' newer data back in.
        if sync.isEnabled {
            UserDefaults.standard.set(true, forKey: SyncController.newEpochPendingKey)
        }
        // Touch ID keys are per vault, so a restored vault with different metadata simply
        // has no enrollment until the user enables it again.
        checkIfVaultExists()
    }
    
    // MARK: - SSH Agent Management
    
    /// Tail of the agent start/stop chain. Each step waits for the previous one, so on a
    /// restart the new server only binds once the old one has fully shut down.
    private var agentLifecycle: Task<Void, Never>?

    func startAgent() {
        guard isAgentEnabled, let socketPath = agentSocketPath else { return }
        print("Starting SSH Agent at \(socketPath)")

        // Ensure only one instance
        stopAgent()

        let server = SSHAgentServer(socketPath: socketPath, delegate: self)
        agentServer = server
        enqueueAgentLifecycle { [weak self] in
            do {
                try await server.start()
            } catch {
                // Not an error if this server was already replaced or stopped.
                guard let self = self, self.agentServer === server else { return }
                self.errorMessage = "Failed to start SSH Agent: \(error.localizedDescription)"
            }
        }
    }

    func stopAgent() {
        guard let server = agentServer else { return }
        agentServer = nil
        enqueueAgentLifecycle {
            try? await server.stop()
        }
    }

    private func enqueueAgentLifecycle(_ work: @escaping @MainActor () async -> Void) {
        let previous = agentLifecycle
        agentLifecycle = Task { @MainActor in
            await previous?.value
            await work()
        }
    }
    
    var agentSocketPath: String? {
        guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let appDir = appSupport.appendingPathComponent("com.sshoebox.app")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("agent.sock").path
    }
}

enum RestoreError: LocalizedError {
    case wrongPassword

    var errorDescription: String? {
        "That isn't the master password of the vault in this backup."
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
