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
    
    public func getAll() throws -> [Credential] {
        try dbManager.reader.read { db in
            try Credential.fetchAll(db)
        }
    }
    
    /// Creates a credential, encrypting both the username and the secret.
    /// - Parameter username: The plaintext username.
    public func createCredential(hostId: String, username: String, type: String, secret: Data, vaultKey: SymmetricKey, isInteractive: Bool = false) throws -> Credential {
        let credential = try Credential.encrypted(
            hostId: hostId, username: username, type: type, secret: secret,
            isInteractive: isInteractive, using: vaultKey
        )
        try save(credential)
        return credential
    }
    
    /// Updates an existing credential, encrypting both the username and the secret.
    /// - Parameter username: The plaintext username.
    public func updateCredential(id: String, hostId: String, username: String, type: String, secret: Data, vaultKey: SymmetricKey, isInteractive: Bool, createdAt: Date) throws -> Credential {
        let credential = try Credential.encrypted(
            id: id,
            hostId: hostId,
            username: username,
            type: type,
            secret: secret,
            isInteractive: isInteractive,
            createdAt: createdAt,
            updatedAt: Date(),
            using: vaultKey
        )
        try dbManager.dbWriter.write { db in
            try credential.update(db)
        }
        return credential
    }

    
    /// Helper to decrypt a credential's secret
    public func decryptSecret(for credential: Credential, vaultKey: SymmetricKey) throws -> Data {
        return try credential.decryptedSecret(using: vaultKey)
    }
}
