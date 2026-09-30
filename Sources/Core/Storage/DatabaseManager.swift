import Foundation
import GRDB

public struct DatabaseManager {
    public let dbWriter: DatabaseWriter
    
    public var reader: DatabaseReader {
        dbWriter
    }
    
    /// Opens (or creates) the vault database at `path`.
    /// - Parameter key: Raw 32-byte SQLCipher key (see `CryptoManager.databaseKey(from:)`).
    ///   When provided, an existing plaintext database is migrated to SQLCipher first.
    ///   When nil, the database is opened unencrypted (tests only).
    public init(path: String, key: Data? = nil) throws {
        let keyString = try key.map(DatabaseManager.rawKeyString)
        var config = Configuration()
        if let keyString {
            config.prepareDatabase { db in
                try db.usePassphrase(keyString)
            }
        }
        
        if let keyString, try DatabaseManager.isPlaintextDatabase(path: path) {
            try DatabaseManager.migrateToEncrypted(at: path, keyString: keyString)
        }
        
        self.dbWriter = try DatabaseQueue(path: path, configuration: config)
        try migrator.migrate(dbWriter)
    }
    
    // In-memory initializer for testing
    public init(inMemory: Bool = true, key: Data? = nil) throws {
        let keyString = try key.map(DatabaseManager.rawKeyString)
        var config = Configuration()
        if let keyString {
            config.prepareDatabase { db in
                try db.usePassphrase(keyString)
            }
        }
        self.dbWriter = try DatabaseQueue(configuration: config)
        try migrator.migrate(dbWriter)
    }
    
    /// SQLCipher raw-key syntax (`x'<64 hex chars>'`). Passing the key this way makes
    /// SQLCipher use it directly instead of running its own KDF over it, and the same
    /// string works for both `sqlite3_key` and `ATTACH ... KEY`.
    private static func rawKeyString(_ key: Data) throws -> String {
        guard key.count == 32 else {
            throw DatabaseError(message: "SQLCipher key must be 32 bytes")
        }
        return "x'" + key.map { String(format: "%02X", $0) }.joined() + "'"
    }
    
    /// True if the file at `path` exists and starts with the plaintext SQLite header.
    /// SQLCipher files start with random salt bytes instead.
    static func isPlaintextDatabase(path: String) throws -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        let header = try handle.read(upToCount: 16) ?? Data()
        return header == Data("SQLite format 3\0".utf8)
    }
    
    /// Migrates a plaintext database to SQLCipher. The encrypted copy is built in a
    /// temporary file and verified (opens with the key, same row counts) before it
    /// atomically replaces the original. On any failure the original is left untouched.
    private static func migrateToEncrypted(at path: String, keyString: String) throws {
        let fm = FileManager.default
        let tempPath = path + ".encrypting"
        try? fm.removeItem(atPath: tempPath)
        
        do {
            let plaintextQueue = try DatabaseQueue(path: path)
            let expectedCounts = try rowCounts(in: plaintextQueue)
            try plaintextQueue.inDatabase { db in
                try db.execute(sql: "ATTACH DATABASE ? AS encrypted KEY ?", arguments: [tempPath, keyString])
                try db.execute(sql: "SELECT sqlcipher_export('encrypted')")
                try db.execute(sql: "DETACH DATABASE encrypted")
            }
            try plaintextQueue.close()
            
            var config = Configuration()
            config.prepareDatabase { db in try db.usePassphrase(keyString) }
            let encryptedQueue = try DatabaseQueue(path: tempPath, configuration: config)
            let actualCounts = try rowCounts(in: encryptedQueue)
            try encryptedQueue.close()
            guard actualCounts == expectedCounts else {
                throw DatabaseError(message: "Encrypted copy does not match the original database")
            }
            
            // rename(2) atomically replaces the plaintext file with the encrypted one.
            guard rename(tempPath, path) == 0 else {
                throw DatabaseError(message: "Failed to replace database: \(String(cString: strerror(errno)))")
            }
            try? fm.removeItem(atPath: path + "-journal")
        } catch {
            try? fm.removeItem(atPath: tempPath)
            throw error
        }
    }
    
    private static func rowCounts(in queue: DatabaseQueue) throws -> [String: Int] {
        try queue.read { db in
            let tables = try String.fetchAll(db, sql: """
                SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """)
            var counts: [String: Int] = [:]
            for table in tables {
                counts[table] = try Int.fetchOne(db, sql: "SELECT count(*) FROM \(table.quotedDatabaseIdentifier)") ?? 0
            }
            return counts
        }
    }
    
    private var migrator: DatabaseMigrator {
        var migrator = DatabaseMigrator()
        
        migrator.registerMigration("v1") { db in
            try db.create(table: "host") { t in
                t.column("id", .text).primaryKey()
                t.column("name", .text).notNull()
                t.column("hostname", .text).notNull()
                t.column("port", .integer).notNull()
                t.column("protocolType", .text).notNull()
                t.column("user", .text).notNull()
                t.column("createdAt", .datetime).notNull()
                t.column("updatedAt", .datetime).notNull()
            }
            
            try db.create(table: "credential") { t in
                t.column("id", .text).primaryKey()
                t.column("hostId", .text).notNull().references("host", onDelete: .cascade)
                t.column("username", .text).notNull()
                t.column("type", .text).notNull()
                t.column("encryptedBlob", .blob).notNull()
                t.column("createdAt", .datetime).notNull()
                t.column("updatedAt", .datetime).notNull()
            }
        }
        
        migrator.registerMigration("v2") { db in
            try db.alter(table: "credential") { t in
                t.add(column: "isInteractive", .boolean).notNull().defaults(to: false)
            }
        }

        migrator.registerMigration("v3") { db in
            try db.create(table: "hostGroup") { t in
                t.column("id", .text).primaryKey()
                t.column("name", .text).notNull()
                t.column("sortOrder", .integer).notNull().defaults(to: 0)
                t.column("createdAt", .datetime).notNull()
            }

            try db.alter(table: "host") { t in
                t.add(column: "groupId", .text).references("hostGroup", onDelete: .setNull)
            }
        }

        migrator.registerMigration("v4") { db in
            try db.create(table: "knownHost") { t in
                t.column("id", .text).primaryKey()
                t.column("hostname", .text).notNull()
                t.column("port", .integer).notNull()
                t.column("keyType", .text).notNull()
                t.column("keyFingerprint", .text).notNull()
                t.column("openSSHPublicKey", .text).notNull()
                t.column("firstSeenAt", .datetime).notNull()
            }
            // Enforce one trusted key per hostname:port pair
            try db.create(
                index: "knownHost_hostname_port",
                on: "knownHost",
                columns: ["hostname", "port"],
                unique: true
            )
        }

        migrator.registerMigration("v5") { db in
            try db.create(table: "passwordHistory") { t in
                t.column("id", .text).primaryKey()
                t.column("credentialId", .text).notNull()
                    .references("credential", onDelete: .cascade)
                t.column("encryptedBlob", .blob).notNull()
                t.column("changedAt", .datetime).notNull()
            }
        }

        migrator.registerMigration("v6") { db in
            try db.alter(table: "host") { t in
                t.add(column: "lastConnectedAt", .datetime)
            }
        }

        return migrator
    }
}
