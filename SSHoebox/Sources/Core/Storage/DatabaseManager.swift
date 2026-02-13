import Foundation
import GRDB

public struct DatabaseManager {
    public let dbWriter: DatabaseWriter
    
    public var reader: DatabaseReader {
        dbWriter
    }
    
    public init(path: String) throws {
        self.dbWriter = try DatabaseQueue(path: path)
        try migrator.migrate(dbWriter)
    }
    
    // In-memory initializer for testing
    public init(inMemory: Bool = true) throws {
        self.dbWriter = try DatabaseQueue()
        try migrator.migrate(dbWriter)
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
        
        return migrator
    }
}
