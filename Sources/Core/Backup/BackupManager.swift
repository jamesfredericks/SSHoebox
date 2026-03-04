import Foundation
import SwiftUI
import CryptoKit
import GRDB

public struct VaultBackup: Codable {
    public let version: Int
    public let timestamp: Date
    public let vaultData: Data
    public let vaultMetadata: Data?  // Keychain metadata (salt + validation), included from v2 onward
    public let checksum: String
}

public class BackupManager: ObservableObject {
    private let dbManager: DatabaseManager
    
    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }
    
    public func createExportData() throws -> Data {
        // Checkpoint any pending WAL journal frames into the main DB file
        // so every write is included in the snapshot we're about to read.
        // checkpoint() requires a write transaction, so we use dbWriter.
        _ = try dbManager.dbWriter.write { db in
            try db.checkpoint(.full)
        }
        
        // Now read the fully-checkpointed DB file bytes.
        let dbPath = dbManager.dbWriter.path
        let backupData = try Data(contentsOf: URL(fileURLWithPath: dbPath))
        
        // Calculate checksum over the consistent snapshot
        let checksum = SHA256.hash(data: backupData).description
        
        // Include vault metadata from Keychain so restore works even on a fresh
        // install (or after a keychain wipe).
        let vaultMetadata = try? KeychainManager.read(account: "vault_metadata")
        
        let backup = VaultBackup(
            version: 2,
            timestamp: Date(),
            vaultData: backupData,
            vaultMetadata: vaultMetadata,
            checksum: checksum
        )
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(backup)
    }
    
    // Note: Restoration requires restarting the app or re-initializing the DatabaseManager.
    // For V1, we replace the file and ask the user to restart.
    public func restore(from data: Data) throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let backup = try decoder.decode(VaultBackup.self, from: data)
        
        // Verify checksum
        let calculated = SHA256.hash(data: backup.vaultData).description
        guard calculated == backup.checksum else {
            throw SecurityError.decryptionFailed // Checksum mismatch
        }
        
        // Restore vault metadata to Keychain if present in backup (v2+).
        // This is critical: without the matching salt the encrypted DB fields
        // cannot be decrypted, producing gibberish.
        if let metadataToRestore = backup.vaultMetadata {
            try KeychainManager.save(metadataToRestore, account: "vault_metadata")
        }
        
        // Replace DB file atomically.
        let dbUrl = URL(fileURLWithPath: dbManager.dbWriter.path)
        try backup.vaultData.write(to: dbUrl, options: .atomic)
        
        // Also remove any stale WAL / SHM sidecar files so SQLite starts clean.
        let walUrl = URL(fileURLWithPath: dbManager.dbWriter.path + "-wal")
        let shmUrl = URL(fileURLWithPath: dbManager.dbWriter.path + "-shm")
        try? FileManager.default.removeItem(at: walUrl)
        try? FileManager.default.removeItem(at: shmUrl)
    }
}

public enum BackupError: Error {
    case databasePathUnavailable
}
