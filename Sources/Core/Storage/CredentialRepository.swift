import Foundation
import GRDB
import CryptoKit

public struct CredentialRepository {
    private let dbManager: DatabaseManager
    
    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }
    
    public func save(_ credential: Credential) throws {
        try dbManager.dbWriter.write { db in
            try credential.save(db)
        }
    }
    
    public func delete(_ credential: Credential) throws {
        try dbManager.dbWriter.write { db in
            try credential.delete(db)
        }
    }
    
    public func getForHost(hostId: String) throws -> [Credential] {
        try dbManager.reader.read { db in
            try Credential.filter(Column("hostId") == hostId).fetchAll(db)
        }
    }
    
    /// Helper to create a credential by encrypting the secret
    public func createCredential(hostId: String, username: String, type: String, secret: Data, vaultKey: SymmetricKey) throws -> Credential {
        let encrypted = try CryptoManager.encrypt(secret, using: vaultKey)
        let credential = Credential(hostId: hostId, username: username, type: type, encryptedBlob: encrypted)
        try save(credential)
        return credential
    }
    
    /// Helper to decrypt a credential's secret
    public func decryptSecret(for credential: Credential, vaultKey: SymmetricKey) throws -> Data {
        return try CryptoManager.decrypt(credential.encryptedBlob, using: vaultKey)
    }
}
