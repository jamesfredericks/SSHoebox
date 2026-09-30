import XCTest
@testable import SSHoeboxCore
import GRDB
import CryptoKit

final class DatabaseEncryptionTests: XCTestCase {
    var tempDir: URL!
    var dbPath: String { tempDir.appendingPathComponent("vault.db").path }

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func header(of path: String) throws -> Data {
        try Data(contentsOf: URL(fileURLWithPath: path)).prefix(16)
    }

    private let plaintextHeader = Data("SQLite format 3\0".utf8)

    func testDatabaseKeyIsDeterministicAndDistinctFromVaultKey() {
        let vaultKey = CryptoManager.generateRandomKey()
        let dbKey = CryptoManager.databaseKey(from: vaultKey)
        XCTAssertEqual(dbKey.count, 32)
        XCTAssertEqual(dbKey, CryptoManager.databaseKey(from: vaultKey))
        XCTAssertNotEqual(dbKey, vaultKey.withUnsafeBytes { Data($0) })
    }

    func testKeyedDatabaseIsEncryptedOnDisk() throws {
        let key = CryptoManager.databaseKey(from: CryptoManager.generateRandomKey())
        let host = SavedHost(name: "Encrypted", hostname: "secret.example.com")
        do {
            let db = try DatabaseManager(path: dbPath, key: key)
            try db.dbWriter.write { db in try host.save(db) }
        }

        XCTAssertNotEqual(try header(of: dbPath), plaintextHeader)
        let contents = try Data(contentsOf: URL(fileURLWithPath: dbPath))
        XCTAssertNil(contents.range(of: Data("secret.example.com".utf8)))

        let reopened = try DatabaseManager(path: dbPath, key: key)
        let fetched = try reopened.reader.read { db in try SavedHost.fetchOne(db, key: host.id) }
        XCTAssertEqual(fetched?.hostname, "secret.example.com")
    }

    func testWrongKeyFailsWithoutDamagingDatabase() throws {
        let key = CryptoManager.databaseKey(from: CryptoManager.generateRandomKey())
        do { _ = try DatabaseManager(path: dbPath, key: key) }
        let before = try Data(contentsOf: URL(fileURLWithPath: dbPath))

        let wrongKey = CryptoManager.databaseKey(from: CryptoManager.generateRandomKey())
        XCTAssertThrowsError(try DatabaseManager(path: dbPath, key: wrongKey))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: dbPath)), before)
    }

    func testPlaintextDatabaseIsMigratedWithDataIntact() throws {
        let hosts = (0..<25).map { SavedHost(name: "Host \($0)", hostname: "10.0.0.\($0)") }
        do {
            let plaintext = try DatabaseManager(path: dbPath)
            try plaintext.dbWriter.write { db in
                for host in hosts { try host.save(db) }
            }
        }
        XCTAssertEqual(try header(of: dbPath), plaintextHeader)

        let key = CryptoManager.databaseKey(from: CryptoManager.generateRandomKey())
        do {
            let migrated = try DatabaseManager(path: dbPath, key: key)
            let count = try migrated.reader.read { db in try SavedHost.fetchCount(db) }
            XCTAssertEqual(count, hosts.count)
        }

        XCTAssertNotEqual(try header(of: dbPath), plaintextHeader)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dbPath + ".encrypting"))

        // Reopening must use the same key format as the migration wrote.
        let reopened = try DatabaseManager(path: dbPath, key: key)
        let names = try reopened.reader.read { db in try SavedHost.fetchAll(db).map(\.name) }
        XCTAssertEqual(Set(names), Set(hosts.map(\.name)))
    }

    func testInvalidKeyLengthIsRejectedBeforeTouchingFile() throws {
        do { _ = try DatabaseManager(path: dbPath) }
        let before = try Data(contentsOf: URL(fileURLWithPath: dbPath))
        XCTAssertThrowsError(try DatabaseManager(path: dbPath, key: Data(repeating: 1, count: 16)))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: dbPath)), before)
    }
}
