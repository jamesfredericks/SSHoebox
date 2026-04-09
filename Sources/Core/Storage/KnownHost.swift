import Foundation
import GRDB

// MARK: - Model

public struct KnownHost: Codable, FetchableRecord, PersistableRecord, Identifiable {
    public static var databaseTableName = "knownHost"

    public var id: String
    public var hostname: String
    public var port: Int
    /// Key algorithm, e.g. "ssh-ed25519", "ecdsa-sha2-nistp256"
    public var keyType: String
    /// SHA-256 fingerprint in OpenSSH display format: "SHA256:base64"
    public var keyFingerprint: String
    /// Full OpenSSH public key string ("type base64") for reconstruction via NIOSSHPublicKey(openSSHPublicKey:)
    public var openSSHPublicKey: String
    public var firstSeenAt: Date

    public init(
        id: String = UUID().uuidString,
        hostname: String,
        port: Int,
        keyType: String,
        keyFingerprint: String,
        openSSHPublicKey: String,
        firstSeenAt: Date = Date()
    ) {
        self.id = id
        self.hostname = hostname
        self.port = port
        self.keyType = keyType
        self.keyFingerprint = keyFingerprint
        self.openSSHPublicKey = openSSHPublicKey
        self.firstSeenAt = firstSeenAt
    }
}

// MARK: - Repository

public struct KnownHostRepository {
    private let dbManager: DatabaseManager

    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }

    public func find(hostname: String, port: Int) throws -> KnownHost? {
        try dbManager.reader.read { db in
            try KnownHost
                .filter(Column("hostname") == hostname && Column("port") == port)
                .fetchOne(db)
        }
    }

    public func save(_ knownHost: KnownHost) throws {
        try dbManager.dbWriter.write { db in
            try knownHost.save(db)
        }
    }

    public func delete(_ knownHost: KnownHost) throws {
        try dbManager.dbWriter.write { db in
            _ = try knownHost.delete(db)
        }
    }

    public func getAll() throws -> [KnownHost] {
        try dbManager.reader.read { db in
            try KnownHost
                .order(Column("hostname"), Column("port"))
                .fetchAll(db)
        }
    }
}
