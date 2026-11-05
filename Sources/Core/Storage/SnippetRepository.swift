import Foundation
import CryptoKit
import GRDB

public struct SnippetRepository {
    private let dbManager: DatabaseManager

    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }

    /// The snippets offered for `hostId`: that host's own first, then the global ones, each
    /// in their saved order. With nil, only the global ones.
    public func snippets(forHost hostId: String?) throws -> [Snippet] {
        try dbManager.reader.read { db in
            let global = try Snippet.filter(Column("hostId") == nil).order(Column("sortOrder"), Column("createdAt")).fetchAll(db)
            guard let hostId else { return global }
            let own = try Snippet.filter(Column("hostId") == hostId).order(Column("sortOrder"), Column("createdAt")).fetchAll(db)
            return own + global
        }
    }

    public func getAll() throws -> [Snippet] {
        try dbManager.reader.read { db in try Snippet.order(Column("sortOrder"), Column("createdAt")).fetchAll(db) }
    }

    /// Adds a snippet, or replaces the one with the same id (keeping its creation date).
    @discardableResult
    public func save(id: String = UUID().uuidString, hostId: String?, name: String, command: String,
                     vaultKey: SymmetricKey) throws -> Snippet {
        try dbManager.dbWriter.write { db in
            let existing = try Snippet.fetchOne(db, key: id)
            let order = try existing?.sortOrder
                ?? (Int.fetchOne(db, sql: "SELECT MAX(sortOrder) FROM snippet") ?? -1) + 1
            let snippet = try Snippet.encrypted(id: id, hostId: hostId, name: name, command: command,
                                                sortOrder: order, createdAt: existing?.createdAt ?? Date(),
                                                updatedAt: Date(), using: vaultKey)
            try snippet.save(db)
            return snippet
        }
    }

    public func delete(_ snippet: Snippet) throws {
        _ = try dbManager.dbWriter.write { db in try snippet.delete(db) }
    }
}
