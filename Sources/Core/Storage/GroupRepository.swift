import Foundation
import GRDB

public struct GroupRepository {
    private let dbManager: DatabaseManager

    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }

    public func getAll() throws -> [HostGroup] {
        try dbManager.reader.read { db in
            try HostGroup.order(Column("sortOrder"), Column("name")).fetchAll(db)
        }
    }

    public func save(_ group: HostGroup) throws {
        try dbManager.dbWriter.write { db in
            try group.save(db)
        }
    }

    public func delete(_ group: HostGroup) throws {
        try dbManager.dbWriter.write { db in
            _ = try group.delete(db)
        }
    }

    /// Persist new sort order for all groups after a drag-reorder.
    public func reorder(_ groups: [HostGroup]) throws {
        try dbManager.dbWriter.write { db in
            for (index, var group) in groups.enumerated() {
                group.sortOrder = index
                try group.save(db)
            }
        }
    }
}
