import Foundation
import GRDB
import CryptoKit

public struct PasswordHistory: Codable, Equatable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "passwordHistory"

    public let id: String
    public let credentialId: String
    public let encryptedBlob: Data
    public let changedAt: Date

    public init(id: String = UUID().uuidString, credentialId: String, encryptedBlob: Data, changedAt: Date = Date()) {
        self.id = id
        self.credentialId = credentialId
        self.encryptedBlob = encryptedBlob
        self.changedAt = changedAt
    }
}

public extension PasswordHistory {
    /// Builds a history entry with the old secret encrypted for this row.
    static func encrypted(
        id: String = UUID().uuidString,
        credentialId: String,
        secret: Data,
        changedAt: Date = Date(),
        using key: SymmetricKey
    ) throws -> PasswordHistory {
        PasswordHistory(
            id: id,
            credentialId: credentialId,
            encryptedBlob: try CryptoManager.encrypt(secret, using: key, context: FieldContext.historySecret(id)),
            changedAt: changedAt
        )
    }

    func decryptedSecret(using key: SymmetricKey) throws -> Data {
        try CryptoManager.decrypt(encryptedBlob, using: key, context: FieldContext.historySecret(id))
    }
}
