import Foundation
import SwiftUI
import Combine
import SSHoeboxCore
import CryptoKit

@MainActor
class VaultViewModel: ObservableObject {
    @Published var isUnlocked: Bool = false
    @Published var isNewUser: Bool = false
    @Published var errorMessage: String?
    
    var dbManager: DatabaseManager?
    private var vaultKey: SymmetricKey?
    
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
            
        } catch {
            self.errorMessage = "Unlock failed: \(error.localizedDescription)"
        }
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
}

struct VaultMetadata: Codable {
    let salt: Data
    let validation: Data
    var version: Int? // Optional for backward compatibility. Nil means 0 (Legacy).
}
