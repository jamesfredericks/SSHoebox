import Foundation
import SSHoeboxCore
import SwiftUI
import CryptoKit

public struct VaultBackup: Codable {
    public let version: Int
    public let timestamp: Date
    public let vaultData: Data
    public let checksum: String
}

public class BackupManager: ObservableObject {
    private let dbManager: DatabaseManager
    
    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }
    
    public func createExportData() throws -> Data {
        // Read raw DB file bytes
        let dbUrl = dbManager.dbWriter.path
        let dbData = try Data(contentsOf: URL(fileURLWithPath: dbUrl))
        
        // Calculate checksum
        let checksum = SHA256.hash(data: dbData).description
        
        // Create wrapper
        let backup = VaultBackup(
            version: 1,
            timestamp: Date(),
            vaultData: dbData,
            checksum: checksum
        )
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(backup)
    }
    
    // Note: Restoration usually requires restarting the app or re-initializing the DatabaseManager
    // For V1, we will replace the file and ask the user to restart.
    public func restore(from data: Data) throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let backup = try decoder.decode(VaultBackup.self, from: data)
        
        // Verify checksum
        let calculated = SHA256.hash(data: backup.vaultData).description
        guard calculated == backup.checksum else {
            throw SecurityError.decryptionFailed // Reusing error or define new one
        }
        
        // Replace DB file
        let dbUrl = URL(fileURLWithPath: dbManager.dbWriter.path)
        
        // Atomic write
        try backup.vaultData.write(to: dbUrl, options: .atomic)
    }
}
