import Foundation
import GRDB
import CryptoKit

public struct PasswordHistoryRepository {
    private let dbManager: DatabaseManager

    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }

    /// Archives `oldSecret` for the given credential so it can be reviewed later.
    public func add(credentialId: String, oldSecret: Data, vaultKey: SymmetricKey) throws {
        let encrypted = try CryptoManager.encrypt(oldSecret, using: vaultKey)
        let record = PasswordHistory(credentialId: credentialId, encryptedBlob: encrypted)
        try dbManager.dbWriter.write { db in
            try record.insert(db)
        }
    }

    /// Returns all history entries for a credential, newest first.
    public func getAll(for credentialId: String) throws -> [PasswordHistory] {
        try dbManager.reader.read { db in
            try PasswordHistory
                .filter(Column("credentialId") == credentialId)
                .order(Column("changedAt").desc)
                .fetchAll(db)
        }
    }

    /// Decrypts a history entry and returns the secret as a String.
    public func decrypt(_ record: PasswordHistory, vaultKey: SymmetricKey) throws -> String {
        let data = try CryptoManager.decrypt(record.encryptedBlob, using: vaultKey)
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Deletes a single history entry.
    public func delete(_ record: PasswordHistory) throws {
        try dbManager.dbWriter.write { db in
            try record.delete(db)
        }
    }
}
