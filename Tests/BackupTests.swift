import XCTest
@testable import SSHoeboxCore
import GRDB
import CryptoKit

final class BackupTests: XCTestCase {
    var tempDir: URL!
    var dbPath: String { tempDir.appendingPathComponent("vault.db").path }
    var metadataPath: String { tempDir.appendingPathComponent("vault_metadata.json").path }

    let vaultKey = CryptoManager.generateRandomKey()
    var dbKey: Data { CryptoManager.databaseKey(from: vaultKey) }

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func makeMetadata() throws -> Data {
        let metadata = VaultMetadata(
            salt: try CryptoManager.generateSalt(),
            validation: try CryptoManager.encrypt(Data("SSHOEBOX_VALID".utf8), using: vaultKey),
            version: 1
        )
        return try JSONEncoder().encode(metadata)
    }

    private func encode(_ backup: VaultBackup) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(backup)
    }

    func testExportIncludesMetadataAndRestoresBothFiles() throws {
        let host = SavedHost(name: "Backup Test", hostname: "localhost")
        let metadata = try makeMetadata()
        let exportData: Data
        do {
            let dbManager = try DatabaseManager(path: dbPath, key: dbKey)
            try dbManager.dbWriter.write { db in try host.save(db) }
            exportData = try BackupManager(dbManager: dbManager).createExportData(vaultMetadata: metadata, vaultKey: vaultKey)
        }

        let backup = try BackupManager.verify(exportData)
        XCTAssertEqual(backup.version, BackupManager.currentVersion)
        XCTAssertEqual(backup.vaultMetadata, metadata)

        // Simulate the vault changing after the backup (new salt, empty DB).
        try FileManager.default.removeItem(atPath: dbPath)
        try makeMetadata().write(to: URL(fileURLWithPath: metadataPath))
        _ = try DatabaseManager(path: dbPath, key: CryptoManager.databaseKey(from: CryptoManager.generateRandomKey()))

        try BackupManager.install(backup, databasePath: dbPath, metadataPath: metadataPath)

        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: metadataPath)), metadata)
        let restored = try DatabaseManager(path: dbPath, key: dbKey)
        let fetched = try restored.reader.read { db in try SavedHost.fetchOne(db, key: host.id) }
        XCTAssertEqual(fetched?.name, "Backup Test")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dbPath + ".restoring"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: metadataPath + ".restoring"))
    }

    func testExportRejectsInvalidMetadata() throws {
        let dbManager = try DatabaseManager(path: dbPath, key: dbKey)
        XCTAssertThrowsError(try BackupManager(dbManager: dbManager).createExportData(vaultMetadata: Data("{}".utf8), vaultKey: vaultKey))
    }

    func testChecksumValidation() throws {
        let badBackup = VaultBackup(
            version: 3, timestamp: Date(), vaultData: Data([0xDE, 0xAD, 0xBE, 0xEF]),
            vaultMetadata: try makeMetadata(), checksum: SHA256.hash(data: Data("other".utf8)).description
        )
        XCTAssertThrowsError(try BackupManager.verify(try encode(badBackup)))
    }

    func testV3BackupWithoutMetadataIsRejected() throws {
        let data = Data("db".utf8)
        let backup = VaultBackup(version: 3, timestamp: Date(), vaultData: data, vaultMetadata: nil,
                                 checksum: SHA256.hash(data: data).description)
        XCTAssertThrowsError(try BackupManager.verify(try encode(backup)))
    }

    func testLegacyBackupWithoutMetadataKeepsCurrentMetadata() throws {
        let current = try makeMetadata()
        try current.write(to: URL(fileURLWithPath: metadataPath))
        let data = Data("db".utf8)
        let backup = VaultBackup(version: 2, timestamp: Date(), vaultData: data, vaultMetadata: nil,
                                 checksum: SHA256.hash(data: data).description)

        try BackupManager.install(try BackupManager.verify(try encode(backup)), databasePath: dbPath, metadataPath: metadataPath)

        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: metadataPath)), current)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: dbPath)), data)
    }

    private func makeAuthenticatedBackup() throws -> VaultBackup {
        let dbManager = try DatabaseManager(path: dbPath, key: dbKey)
        let data = try BackupManager(dbManager: dbManager).createExportData(vaultMetadata: makeMetadata(), vaultKey: vaultKey)
        return try BackupManager.verify(data)
    }

    func testBackupIsAuthenticOnlyWithItsVaultKey() throws {
        let backup = try makeAuthenticatedBackup()
        XCTAssertNotNil(backup.authenticationCode)
        XCTAssertTrue(backup.isAuthentic(using: vaultKey))
        XCTAssertFalse(backup.isAuthentic(using: CryptoManager.generateRandomKey()))
    }

    func testTamperedBackupIsNotAuthentic() throws {
        let backup = try makeAuthenticatedBackup()
        var tamperedDB = backup.vaultData
        tamperedDB[tamperedDB.count - 1] ^= 0x01
        // Recomputing the plain checksum is easy; the MAC is what catches it.
        let swappedDB = VaultBackup(version: backup.version, timestamp: backup.timestamp, vaultData: tamperedDB,
                                    vaultMetadata: backup.vaultMetadata, checksum: SHA256.hash(data: tamperedDB).description,
                                    authenticationCode: backup.authenticationCode)
        XCTAssertFalse(try BackupManager.verify(try encode(swappedDB)).isAuthentic(using: vaultKey))

        let swappedMetadata = VaultBackup(version: backup.version, timestamp: backup.timestamp, vaultData: backup.vaultData,
                                          vaultMetadata: try makeMetadata(), checksum: backup.checksum,
                                          authenticationCode: backup.authenticationCode)
        XCTAssertFalse(try BackupManager.verify(try encode(swappedMetadata)).isAuthentic(using: vaultKey))
    }

    func testV4BackupWithoutMACIsRejected() throws {
        let backup = try makeAuthenticatedBackup()
        let stripped = VaultBackup(version: 4, timestamp: backup.timestamp, vaultData: backup.vaultData,
                                   vaultMetadata: backup.vaultMetadata, checksum: backup.checksum)
        XCTAssertThrowsError(try BackupManager.verify(try encode(stripped)))
    }

    func testExportRejectsMetadataOfAnotherVault() throws {
        let dbManager = try DatabaseManager(path: dbPath, key: dbKey)
        XCTAssertThrowsError(try BackupManager(dbManager: dbManager).createExportData(
            vaultMetadata: makeMetadata(), vaultKey: CryptoManager.generateRandomKey()))
    }

    func testFutureVersionIsRejected() throws {
        let data = Data("db".utf8)
        let backup = VaultBackup(version: 99, timestamp: Date(), vaultData: data, vaultMetadata: try makeMetadata(),
                                 checksum: SHA256.hash(data: data).description)
        XCTAssertThrowsError(try BackupManager.verify(try encode(backup)))
    }
}
