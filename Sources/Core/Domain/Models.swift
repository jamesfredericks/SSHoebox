import Foundation
import GRDB

// MARK: - HostGroup

public struct HostGroup: Codable, FetchableRecord, PersistableRecord, Identifiable {
    public static var databaseTableName = "hostGroup"
    
    public var id: String
    public var name: String
    public var sortOrder: Int
    public var createdAt: Date
    
    public init(id: String = UUID().uuidString,
                name: String,
                sortOrder: Int = 0,
                createdAt: Date = Date()) {
        self.id = id
        self.name = name
        self.sortOrder = sortOrder
        self.createdAt = createdAt
    }
}

// MARK: - SavedHost

public struct SavedHost: Codable, FetchableRecord, PersistableRecord, Identifiable {
    public static var databaseTableName = "host"
    
    public var id: String
    public var name: String
    public var hostname: String
    public var port: Int
    public var protocolType: String // "ssh", "sftp", "ftp"
    public var user: String // Default user for display or connection
    public var groupId: String? // Optional reference to HostGroup
    public var createdAt: Date
    public var updatedAt: Date
    
    public init(id: String = UUID().uuidString,
                name: String,
                hostname: String,
                port: Int = 22,
                protocolType: String = "ssh",
                user: String = "",
                groupId: String? = nil,
                createdAt: Date = Date(),
                updatedAt: Date = Date()) {
        self.id = id
        self.name = name
        self.hostname = hostname
        self.port = port
        self.protocolType = protocolType
        self.user = user
        self.groupId = groupId
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

// MARK: - Credential

public struct Credential: Codable, FetchableRecord, PersistableRecord, Identifiable {
    public static var databaseTableName = "credential"
    
    public var id: String
    public var hostId: String
    public var username: String
    public var type: String // "password", "key"
    public var encryptedBlob: Data // Encrypted JSON or raw bytes
    public var isInteractive: Bool // For YubiKey, hardware tokens, etc.
    public var createdAt: Date
    public var updatedAt: Date
    
    public init(id: String = UUID().uuidString,
                hostId: String,
                username: String,
                type: String,
                encryptedBlob: Data,
                isInteractive: Bool = false,
                createdAt: Date = Date(),
                updatedAt: Date = Date()) {
        self.id = id
        self.hostId = hostId
        self.username = username
        self.type = type
        self.encryptedBlob = encryptedBlob
        self.isInteractive = isInteractive
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}
