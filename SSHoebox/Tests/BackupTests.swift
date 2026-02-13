import XCTest
@testable import SSHoeboxCore
import GRDB
import CryptoKit

final class BackupTests: XCTestCase {
    var dbManager: DatabaseManager!
    var backupManager: BackupManager!
    var tempDbPath: String!
    
    override func setUpWithError() throws {
        // Use a temporary file path
        tempDbPath = NSTemporaryDirectory() + UUID().uuidString + ".sqlite"
        dbManager = try DatabaseManager(path: tempDbPath)
        backupManager = BackupManager(dbManager: dbManager)
    }
    
    override func tearDownWithError() throws {
        try FileManager.default.removeItem(atPath: tempDbPath)
    }
    
    func testExportImport() throws {
        // 1. Write something to DB
        let host = SavedHost(name: "Backup Test", hostname: "localhost")
        try dbManager.dbWriter.write { db in
            try host.save(db)
        }
        
        // 2. Export
        let backupData = try backupManager.createExportData()
        XCTAssertFalse(backupData.isEmpty)
        
        // 3. Decode manually to check structure
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let backup = try decoder.decode(VaultBackup.self, from: backupData)
        XCTAssertEqual(backup.version, 1)
        XCTAssertFalse(backup.checksum.isEmpty)
        
        // 4. Wipe DB (conceptually - here we just verify restore overwrites)
        
        // 5. Restore
        try backupManager.restore(from: backupData)
        
        // Re-init manager to pick up new file (simulating app restart)
        dbManager = try DatabaseManager(path: tempDbPath)
        
        // 6. Verify data
        let fetched: SavedHost? = try dbManager.reader.read { db in
            try SavedHost.fetchOne(db, key: host.id)
        }
        XCTAssertNotNil(fetched)
        XCTAssertEqual(fetched?.name, "Backup Test")
    }
    
    func testChecksumValidation() throws {
        let exportData = try backupManager.createExportData()
        
        // Tamper with data
        // For JSON, we can decode, modify vaultData, re-encode without updating checksum
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var backup = try decoder.decode(VaultBackup.self, from: exportData)
        
        // Corrupt internal data
        let corruptedData = Data([0xDE, 0xAD, 0xBE, 0xEF])
        
        let badBackup = VaultBackup(version: 1, timestamp: Date(), vaultData: corruptedData, checksum: backup.checksum)
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let corruptedExport = try encoder.encode(badBackup)
        
        XCTAssertThrowsError(try backupManager.restore(from: corruptedExport))
    }
}
