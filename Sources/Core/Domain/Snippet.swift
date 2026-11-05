import Foundation
import CryptoKit
import GRDB

/// A saved command, sent to a terminal session with one click. A snippet with a `hostId`
/// belongs to that host; one without is offered for every host. Name and command are
/// encrypted for the row, like host fields. Schema v9; synced like hosts.
public struct Snippet: Codable, Equatable, FetchableRecord, PersistableRecord, Identifiable {
    public static var databaseTableName = "snippet"

    public var id: String
    public var hostId: String?
    public var name: String
    public var command: String
    public var sortOrder: Int
    public var createdAt: Date
    public var updatedAt: Date

    public init(id: String = UUID().uuidString, hostId: String?, name: String, command: String,
                sortOrder: Int = 0, createdAt: Date = Date(), updatedAt: Date = Date()) {
        self.id = id
        self.hostId = hostId
        self.name = name
        self.command = command
        self.sortOrder = sortOrder
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    /// Builds a snippet with its name and command encrypted for this row.
    public static func encrypted(id: String = UUID().uuidString, hostId: String?, name: String, command: String,
                                 sortOrder: Int = 0, createdAt: Date = Date(), updatedAt: Date = Date(),
                                 using key: SymmetricKey) throws -> Snippet {
        Snippet(id: id, hostId: hostId,
                name: try CryptoManager.encryptString(name, using: key, context: FieldContext.snippet("name", id)),
                command: try CryptoManager.encryptString(command, using: key, context: FieldContext.snippet("command", id)),
                sortOrder: sortOrder, createdAt: createdAt, updatedAt: updatedAt)
    }

    public func decryptedName(using key: SymmetricKey) -> String {
        (try? CryptoManager.decryptString(name, using: key, context: FieldContext.snippet("name", id))) ?? ""
    }

    public func decryptedCommand(using key: SymmetricKey) -> String {
        (try? CryptoManager.decryptString(command, using: key, context: FieldContext.snippet("command", id))) ?? ""
    }
}
