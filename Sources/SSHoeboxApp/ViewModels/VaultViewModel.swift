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
    var isBiometricEnrolled: Bool { BiometricAuthManager.isBiometricEnrolled }
    var biometricTypeName: String { BiometricAuthManager.biometricTypeName() }
    var biometricSymbolName: String { BiometricAuthManager.biometricSymbolName() }
    
    var dbManager: DatabaseManager?
    var vaultKey: SymmetricKey?
    private var idleMonitor: IdleMonitor?
    private var cancellables = Set<AnyCancellable>()
    
    // Path to the vault database
    private var dbPath: String {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let appDir = appSupport.appendingPathComponent("com.sshoebox.app")
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        return appDir.appendingPathComponent("vault.db").path
    }
    
    init() {
        checkIfVaultExists()
    }
    
    func checkIfVaultExists() {
        // Simple check: does the DB file exist?
        // In a real app we might verify keychain item existence too.
        isNewUser = !FileManager.default.fileExists(atPath: dbPath)
    }
    
    func createVault(password: String) {
        do {
            let salt = try CryptoManager.generateSalt()
            let key = try CryptoManager.deriveKey(password: password, salt: salt)
            
            // Save salt to Keychain or separate header file. 
            // For v1 simplicity, we'll store a "validation hash" in Keychain to verify password quickly,
            // and we might need to store the salt. 
            // Actually, best practice: store salt in the DB header or a sidecar config file. 
            // Let's store salt in Keychain for now alongside a validation token.
            
            // 1. Create DB
            let manager = try DatabaseManager(path: dbPath)
            self.dbManager = manager
            self.vaultKey = key
            
            // 2. Persist Salt & Validation
            // Validation: Encrypt a known constant "valid" with the key. If we can decrypt it later, key is good.
            let validationData = try CryptoManager.encrypt("SSHOEBOX_VALID".data(using: .utf8)!, using: key)
            
            let vaultMetadata = VaultMetadata(salt: salt, validation: validationData, version: 1)
            let metadataData = try JSONEncoder().encode(vaultMetadata)
            try KeychainManager.save(metadataData, account: "vault_metadata")
            
            self.isUnlocked = true
            self.isNewUser = false
            self.errorMessage = nil
            
            // Start auto-lock monitoring
            startAutoLockMonitoring()
            
        } catch {
            self.errorMessage = "Failed to create vault: \(error.localizedDescription)"
        }
    }
    
    func unlock(password: String) {
        do {
            // 1. Retrieve Salt & Validation from Keychain
            let metadataData = try KeychainManager.read(account: "vault_metadata")
            let metadata = try JSONDecoder().decode(VaultMetadata.self, from: metadataData)
            
            // 2. Derive Key
            let key = try CryptoManager.deriveKey(password: password, salt: metadata.salt)
            
            // 3. Verify Key
            let decryptedValidation = try CryptoManager.decrypt(metadata.validation, using: key)
            guard let validationString = String(data: decryptedValidation, encoding: .utf8), 
                  validationString == "SSHOEBOX_VALID" else {
                self.errorMessage = "Invalid password."
                return
            }
            
            // 4. Open DB
            let manager = try DatabaseManager(path: dbPath)
            self.dbManager = manager
            self.vaultKey = key
            
            // 5. Check Migration
            if (metadata.version ?? 0) < 1 {
                try performMetadataEncryption(db: manager, key: key)
                var newMetadata = metadata
                newMetadata.version = 1
                let newMetadataData = try JSONEncoder().encode(newMetadata)
                try KeychainManager.save(newMetadataData, account: "vault_metadata")
            }
            
            self.isUnlocked = true
            self.errorMessage = nil
            
            // Prompt biometric enrollment if available and not yet enrolled
            if BiometricAuthManager.isBiometricAvailable() && !BiometricAuthManager.isBiometricEnrolled {
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
                let key = try await BiometricAuthManager.unlockWithBiometrics()
                
                // Validate the key against the stored validation token
                let metadataData = try KeychainManager.read(account: "vault_metadata")
                let metadata = try JSONDecoder().decode(VaultMetadata.self, from: metadataData)
                let decryptedValidation = try CryptoManager.decrypt(metadata.validation, using: key)
                guard let validationString = String(data: decryptedValidation, encoding: .utf8),
                      validationString == "SSHOEBOX_VALID" else {
                    self.errorMessage = "Biometric unlock failed: key mismatch."
                    return
                }
                
                let manager = try DatabaseManager(path: dbPath)
                self.dbManager = manager
                self.vaultKey = key
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
        guard let key = vaultKey else { return }
        do {
            try BiometricAuthManager.enrollBiometric(vaultKey: key)
            self.showBiometricSetupPrompt = false
            self.errorMessage = nil
        } catch {
            // Keep the setup prompt open and surface the error to the user
            self.errorMessage = "Failed to enable biometric unlock: \(error.localizedDescription)"
        }
    }
    
    /// Disable biometric unlock and remove the stored key.
    func disableBiometrics() {
        BiometricAuthManager.revokeBiometric()
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
                if isIdle {
                    self?.lock()
                }
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
        // Delete DB
        try? FileManager.default.removeItem(atPath: dbPath)
        
        // Delete Keychain Item
        try? KeychainManager.delete(account: "vault_metadata")
        
        self.lock()
        self.checkIfVaultExists()
        self.errorMessage = nil
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

struct VaultMetadata: Codable {
    let salt: Data
    let validation: Data
    var version: Int? // Optional for backward compatibility. Nil means 0 (Legacy).
}
