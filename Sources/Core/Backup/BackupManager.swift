import Foundation
import SwiftUI
import CryptoKit
import GRDB

public struct VaultBackup: Codable {
    public let version: Int
    public let timestamp: Date
    public let vaultData: Data
    public let vaultMetadata: Data?  // vault_metadata.json contents. Required from v3 onward.
    public let checksum: String
    /// HMAC-SHA256 over the version, database and metadata, keyed from the vault key.
    /// Required from v4 onward; older backups can only be checked for accidental corruption.
    public let authenticationCode: Data?

    public init(version: Int, timestamp: Date, vaultData: Data, vaultMetadata: Data?, checksum: String,
                authenticationCode: Data? = nil) {
        self.version = version
        self.timestamp = timestamp
        self.vaultData = vaultData
        self.vaultMetadata = vaultMetadata
        self.checksum = checksum
        self.authenticationCode = authenticationCode
    }

    /// The decoded vault metadata carried by the backup (nil for v2 backups without it).
    public var metadata: VaultMetadata? {
        vaultMetadata.flatMap { try? JSONDecoder().decode(VaultMetadata.self, from: $0) }
    }

    /// Whether the backup was made from the vault whose key is `vaultKey` and hasn't been
    /// altered since. Always false for backups made before v4, which carry no MAC.
    public func isAuthentic(using vaultKey: SymmetricKey) -> Bool {
        guard let authenticationCode else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(
            authenticationCode,
            authenticating: Self.macInput(version: version, vaultData: vaultData, vaultMetadata: vaultMetadata),
            using: Self.macKey(from: vaultKey)
        )
    }

    static func macKey(from vaultKey: SymmetricKey) -> SymmetricKey {
        CryptoManager.subkey(from: vaultKey, label: "com.sshoebox.backup-hmac.v1")
    }

    /// Length-prefixed so no two different (database, metadata) pairs share an input.
    static func macInput(version: Int, vaultData: Data, vaultMetadata: Data?) -> Data {
        var input = Data("SSHoebox backup v\(version)\n".utf8)
        for part in [vaultData, vaultMetadata ?? Data()] {
            withUnsafeBytes(of: UInt64(part.count).bigEndian) { input.append(contentsOf: $0) }
            input.append(part)
        }
        return input
    }
}

public class BackupManager: ObservableObject {
    /// v3: vaultData may be SQLCipher-encrypted and vaultMetadata is always present.
    /// v4: adds `authenticationCode`.
    public static let currentVersion = 4

    private let dbManager: DatabaseManager

    public init(dbManager: DatabaseManager) {
        self.dbManager = dbManager
    }

    /// Snapshots the database file together with the vault metadata needed to open it.
    /// - Parameters:
    ///   - vaultMetadata: The current `vault_metadata.json` contents.
    ///   - vaultKey: The open vault's key, used to authenticate the backup.
    public func createExportData(vaultMetadata: Data, vaultKey: SymmetricKey) throws -> Data {
        let metadata = try JSONDecoder().decode(VaultMetadata.self, from: vaultMetadata)
        try metadata.validateStructure()
        guard metadata.isValid(vaultKey) else { throw BackupError.invalidMetadata }

        // Hold the writer lock while reading the file so no write lands mid-copy.
        // checkpoint() flushes WAL frames if WAL is ever enabled; it must run outside a transaction.
        let dbPath = dbManager.dbWriter.path
        let backupData = try dbManager.dbWriter.writeWithoutTransaction { db -> Data in
            try db.checkpoint(.full)
            return try Data(contentsOf: URL(fileURLWithPath: dbPath))
        }

        let checksum = SHA256.hash(data: backupData).description

        let mac = HMAC<SHA256>.authenticationCode(
            for: VaultBackup.macInput(version: Self.currentVersion, vaultData: backupData, vaultMetadata: vaultMetadata),
            using: VaultBackup.macKey(from: vaultKey)
        )
        let backup = VaultBackup(
            version: Self.currentVersion,
            timestamp: Date(),
            vaultData: backupData,
            vaultMetadata: vaultMetadata,
            checksum: checksum,
            authenticationCode: Data(mac)
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(backup)
    }

    /// Decodes a backup and checks its structure and checksum without touching the current
    /// vault. Authenticity needs the backup's vault key: see `VaultBackup.isAuthentic(using:)`.
    public static func verify(_ data: Data) throws -> VaultBackup {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let backup = try decoder.decode(VaultBackup.self, from: data)

        guard backup.version <= currentVersion else {
            throw BackupError.unsupportedVersion(backup.version)
        }
        guard SHA256.hash(data: backup.vaultData).description == backup.checksum else {
            throw BackupError.checksumMismatch
        }
        if backup.vaultMetadata != nil {
            guard let metadata = backup.metadata, (try? metadata.validateStructure()) != nil else {
                throw BackupError.invalidMetadata
            }
        } else if backup.version >= 3 {
            throw BackupError.invalidMetadata
        }
        if backup.version >= 4 && backup.authenticationCode == nil {
            throw BackupError.notAuthentic
        }
        return backup
    }

    /// Replaces the vault database (and metadata, when the backup carries it) with the
    /// backup's contents. All database connections to `databasePath` must be closed first.
    ///
    /// Both files are staged next to their destinations before either is swapped in, so a
    /// write failure leaves the current vault intact.
    public static func install(_ backup: VaultBackup, databasePath: String, metadataPath: String) throws {
        let fm = FileManager.default
        let dbStage = databasePath + ".restoring"
        let metadataStage = metadataPath + ".restoring"
        defer {
            try? fm.removeItem(atPath: dbStage)
            try? fm.removeItem(atPath: metadataStage)
        }

        try backup.vaultData.write(to: URL(fileURLWithPath: dbStage))
        if let metadata = backup.vaultMetadata {
            try metadata.write(to: URL(fileURLWithPath: metadataStage))
        }

        // A leftover journal from the old database must not be replayed onto the restored one.
        for suffix in ["-journal", "-wal", "-shm"] {
            try? fm.removeItem(atPath: databasePath + suffix)
        }

        try atomicReplace(databasePath, with: dbStage)
        if backup.vaultMetadata != nil {
            try atomicReplace(metadataPath, with: metadataStage)
        }
    }

    private static func atomicReplace(_ destination: String, with source: String) throws {
        guard rename(source, destination) == 0 else {
            throw BackupError.fileReplaceFailed(String(cString: strerror(errno)))
        }
    }
}

public enum BackupError: LocalizedError {
    case databasePathUnavailable
    case unsupportedVersion(Int)
    case checksumMismatch
    case invalidMetadata
    case fileReplaceFailed(String)
    case notAuthentic

    public var errorDescription: String? {
        switch self {
        case .databasePathUnavailable:
            return "The vault database path is unavailable."
        case .unsupportedVersion(let version):
            return "This backup (format v\(version)) was created by a newer version of SSHoebox."
        case .checksumMismatch:
            return "The backup file is corrupted (checksum mismatch)."
        case .invalidMetadata:
            return "The backup is missing valid vault metadata and cannot be restored."
        case .fileReplaceFailed(let reason):
            return "Could not replace vault files: \(reason)"
        case .notAuthentic:
            return "This backup has been modified, or it doesn't belong to the vault whose password was given."
        }
    }
}
