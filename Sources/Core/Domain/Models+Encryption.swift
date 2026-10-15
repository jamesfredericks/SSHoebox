import Foundation
import CryptoKit
import GRDB

/// Associated-data labels for field encryption. Each names the table, column and row, so a
/// ciphertext only decrypts in the place it was written (see `CryptoManager.encrypt(_:using:context:)`).
enum FieldContext {
    static func host(_ column: String, _ id: String) -> String { "host.\(column):\(id)" }
    static func credentialUsername(_ id: String) -> String { "credential.username:\(id)" }
    static func credentialSecret(_ id: String) -> String { "credential.secret:\(id)" }
    static func historySecret(_ id: String) -> String { "passwordHistory.secret:\(id)" }
}

public extension SavedHost {
    /// Builds a host with its name, hostname and user encrypted for this row.
    static func encrypted(
        id: String = UUID().uuidString,
        name: String,
        hostname: String,
        port: Int,
        protocolType: String,
        user: String,
        groupId: String?,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        lastConnectedAt: Date? = nil,
        using key: SymmetricKey
    ) throws -> SavedHost {
        SavedHost(
            id: id,
            name: try CryptoManager.encryptString(name, using: key, context: FieldContext.host("name", id)),
            hostname: try CryptoManager.encryptString(hostname, using: key, context: FieldContext.host("hostname", id)),
            port: port,
            protocolType: protocolType,
            user: try CryptoManager.encryptString(user, using: key, context: FieldContext.host("user", id)),
            groupId: groupId,
            createdAt: createdAt,
            updatedAt: updatedAt,
            lastConnectedAt: lastConnectedAt
        )
    }

    func decryptedName(using key: SymmetricKey) -> String {
        (try? CryptoManager.decryptString(name, using: key, context: FieldContext.host("name", id))) ?? name
    }

    func decryptedHostname(using key: SymmetricKey) -> String {
        (try? CryptoManager.decryptString(hostname, using: key, context: FieldContext.host("hostname", id))) ?? hostname
    }

    func decryptedUser(using key: SymmetricKey) -> String {
        (try? CryptoManager.decryptString(user, using: key, context: FieldContext.host("user", id))) ?? user
    }
}

public extension Credential {
    /// Builds a credential with its username and secret encrypted for this row.
    static func encrypted(
        id: String = UUID().uuidString,
        hostId: String,
        username: String,
        type: String,
        secret: Data,
        isInteractive: Bool,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        using key: SymmetricKey
    ) throws -> Credential {
        Credential(
            id: id,
            hostId: hostId,
            username: try CryptoManager.encryptString(username, using: key, context: FieldContext.credentialUsername(id)),
            type: type,
            encryptedBlob: try CryptoManager.encrypt(secret, using: key, context: FieldContext.credentialSecret(id)),
            isInteractive: isInteractive,
            createdAt: createdAt,
            updatedAt: updatedAt
        )
    }

    func decryptedUsername(using key: SymmetricKey) -> String {
        (try? CryptoManager.decryptString(username, using: key, context: FieldContext.credentialUsername(id))) ?? username
    }

    func decryptedSecret(using key: SymmetricKey) throws -> Data {
        try CryptoManager.decrypt(encryptedBlob, using: key, context: FieldContext.credentialSecret(id))
    }
}

/// Re-encrypts every encrypted field in the context-bound format, and encrypts values that
/// older versions stored in plaintext (host fields before metadata v1, and credential
/// usernames saved from Add Host or import). Runs on unlock until it has completed once.
public enum FieldEncryptionMigration {
    static let formatKey = "fieldEncryptionFormat"
    static let currentFormat = "2"

    public static func isNeeded(_ dbManager: DatabaseManager) throws -> Bool {
        try dbManager.reader.read { db in
            try String.fetchOne(db, sql: "SELECT value FROM vaultInfo WHERE key = ?", arguments: [formatKey]) != currentFormat
        }
    }

    /// Runs in a single transaction, so a failure leaves the vault as it was.
    public static func run(_ dbManager: DatabaseManager, vaultKey key: SymmetricKey) throws {
        try dbManager.dbWriter.write { db in
            for var host in try SavedHost.fetchAll(db) {
                host.name = try migrateString(host.name, key: key, context: FieldContext.host("name", host.id))
                host.hostname = try migrateString(host.hostname, key: key, context: FieldContext.host("hostname", host.id))
                host.user = try migrateString(host.user, key: key, context: FieldContext.host("user", host.id))
                try host.update(db)
            }

            for var credential in try Credential.fetchAll(db) {
                credential.username = try migrateString(
                    credential.username, key: key, context: FieldContext.credentialUsername(credential.id)
                )
                // Secrets were always encrypted; one that can't be decrypted is left untouched.
                if let secret = try? credential.decryptedSecret(using: key) {
                    credential.encryptedBlob = try CryptoManager.encrypt(
                        secret, using: key, context: FieldContext.credentialSecret(credential.id)
                    )
                }
                try credential.update(db)
            }

            for record in try PasswordHistory.fetchAll(db) {
                guard let secret = try? record.decryptedSecret(using: key) else { continue }
                let migrated = try PasswordHistory.encrypted(
                    id: record.id, credentialId: record.credentialId, secret: secret,
                    changedAt: record.changedAt, using: key
                )
                try migrated.update(db)
            }

            try db.execute(
                sql: "INSERT OR REPLACE INTO vaultInfo (key, value) VALUES (?, ?)",
                arguments: [formatKey, currentFormat]
            )
        }
    }

    /// Re-encrypts a stored string field for `context`. A ciphertext is decrypted and sealed
    /// again; a value older versions saved unencrypted is encrypted. A value that looks like a
    /// ciphertext but doesn't decrypt is kept as is rather than encrypted a second time.
    static func migrateString(_ value: String, key: SymmetricKey, context: String) throws -> String {
        if let plaintext = try? CryptoManager.decryptString(value, using: key, context: context) {
            return try CryptoManager.encryptString(plaintext, using: key, context: context)
        }
        if let data = Data(base64Encoded: value), data.count >= 28 {
            // nonce (12) + tag (16): long enough to be a damaged or foreign ciphertext
            return value
        }
        return try CryptoManager.encryptString(value, using: key, context: context)
    }
}
