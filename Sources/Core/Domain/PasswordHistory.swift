import Foundation
import GRDB

public struct PasswordHistory: Codable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "passwordHistory"

    public let id: String
    public let credentialId: String
    public let encryptedBlob: Data
    public let changedAt: Date

    public init(credentialId: String, encryptedBlob: Data) {
        self.id = UUID().uuidString
        self.credentialId = credentialId
        self.encryptedBlob = encryptedBlob
        self.changedAt = Date()
    }
}
