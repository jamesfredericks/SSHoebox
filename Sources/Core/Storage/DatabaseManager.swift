import Foundation
import GRDB

public struct DatabaseManager {
    public let dbWriter: DatabaseWriter
    
    public var reader: DatabaseReader {
        dbWriter
    }
    
    public init(path: String, passphrase: Data? = nil) throws {
        var config = Configuration()
        if let passphrase = passphrase {
            config.prepareDatabase { db in
                try db.usePassphrase(passphrase)
            }
        }
        
        // Handle migration if the current DB is plaintext but we want encryption
        if let passphrase = passphrase, FileManager.default.fileExists(atPath: path) && !DatabaseManager.isDatabaseEncrypted(path: path) {
            try DatabaseManager.migrateToEncrypted(at: path, passphrase: passphrase)
        }
        
        self.dbWriter = try DatabaseQueue(path: path, configuration: config)
        try migrator.migrate(dbWriter)
    }
    
    // In-memory initializer for testing
    public init(inMemory: Bool = true, passphrase: Data? = nil) throws {
        var config = Configuration()
        if let passphrase = passphrase {
            config.prepareDatabase { db in
                try db.usePassphrase(passphrase)
            }
        }
        self.dbWriter = try DatabaseQueue(configuration: config)
        try migrator.migrate(dbWriter)
    }
    
    /// Checks if a database is currently encrypted by attempting to read it without a key.
    private static func isDatabaseEncrypted(path: String) -> Bool {
        do {
            let db = try DatabaseQueue(path: path)
            try db.read { db in
                _ = try Int.fetchOne(db, sql: "SELECT count(*) FROM sqlite_master")
            }
            return false // Read succeeded (plaintext)
        } catch {
            return true // Read failed (likely encrypted)
        }
    }
    
    /// Migrates a plaintext database to an encrypted SQLCipher database by exporting to a temporary file.
    private static func migrateToEncrypted(at path: String, passphrase: Data) throws {
        let tempPath = path + ".tmp"
        if FileManager.default.fileExists(atPath: tempPath) {
            try FileManager.default.removeItem(atPath: tempPath)
        }
        
        let plaintextQueue = try DatabaseQueue(path: path)
        try plaintextQueue.inDatabase { db in
            // Use SQLCipher export to move data to a keyed temporary database
            let hexPassphrase = passphrase.map { String(format: "%02hhx", $0) }.joined()
            try db.execute(sql: "ATTACH DATABASE ? AS encrypted KEY ?", arguments: [tempPath, hexPassphrase])
            try db.execute(sql: "SELECT sqlcipher_export('encrypted')")
            try db.execute(sql: "DETACH DATABASE encrypted")
        }
        
        // Replace old plaintext DB with the new encrypted one
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.moveItem(atPath: tempPath, toPath: path)
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

        return migrator
    }
}
