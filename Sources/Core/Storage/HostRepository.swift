import Foundation
import GRDB

public struct HostRepository {
    private let dbManager: DatabaseManager
    
    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }
    
    public func save(_ host: SavedHost) throws {
        try dbManager.dbWriter.write { db in
            try host.save(db)
        }
    }
    
    public func delete(_ host: SavedHost) throws {
        try dbManager.dbWriter.write { db in
            try host.delete(db)
        }
    }
    
    public func getAll() throws -> [SavedHost] {
        try dbManager.reader.read { db in
            try SavedHost.fetchAll(db)
        }
    }
    
    public func get(id: String) throws -> SavedHost? {
        try dbManager.reader.read { db in
            try SavedHost.fetchOne(db, key: id)
        }
    }
}
