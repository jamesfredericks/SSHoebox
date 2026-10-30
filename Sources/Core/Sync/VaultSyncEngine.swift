import Foundation
import CryptoKit
import GRDB

/// Keeps a vault the same on several Macs through a folder that a cloud service syncs
/// (iCloud Drive, Dropbox, OneDrive...).
///
/// Each Mac keeps its own `vault.db` and writes only its own file in the folder: a sealed
/// snapshot of the whole vault plus the synced settings. A sync pass reads the other Macs'
/// files, merges them record by record into the local database (see `VaultRecords.merge`),
/// and rewrites this Mac's file if anything changed. Because no two Macs write the same file,
/// the cloud service never has to resolve a conflict, and a conflict copy it makes anyway
/// is just one more snapshot to merge.
///
/// ```
/// <folder>/vault_metadata.json          lets another Mac join (unlock with the master password)
/// <folder>/devices/<deviceID>.sshoeboxsync
/// ```
///
/// Snapshots are sealed with AES-GCM under a subkey of the vault key, so the folder reveals
/// nothing without the master password, and a file that was altered is ignored.
public struct VaultSyncEngine {
    public static let metadataFileName = "vault_metadata.json"
    public static let devicesDirectoryName = "devices"
    public static let fileExtension = "sshoeboxsync"
    /// Used inside a chosen folder that already holds other files.
    public static let subfolderName = "SSHoebox Sync"

    static let fileFormat = 1
    static let snapshotSchema = 1

    let dbManager: DatabaseManager
    let metadata: VaultMetadata
    let metadataData: Data
    let syncKey: SymmetricKey
    let folder: URL
    let deviceID: String
    let deviceName: String

    var vaultID: String { metadata.identifier }
    private var devicesURL: URL { folder.appendingPathComponent(Self.devicesDirectoryName) }
    private var ownFileURL: URL { devicesURL.appendingPathComponent("\(deviceID).\(Self.fileExtension)") }

    /// - Parameter vaultMetadata: The open vault's `vault_metadata.json` contents.
    public init(
        dbManager: DatabaseManager,
        vaultKey: SymmetricKey,
        vaultMetadata: Data,
        folder: URL,
        deviceID: String,
        deviceName: String
    ) throws {
        let metadata = try JSONDecoder().decode(VaultMetadata.self, from: vaultMetadata)
        guard metadata.isValid(vaultKey) else { throw VaultMetadataError.keyMismatch }
        self.dbManager = dbManager
        self.metadata = metadata
        self.metadataData = vaultMetadata
        self.syncKey = CryptoManager.subkey(from: vaultKey, label: "com.sshoebox.sync.v1")
        self.folder = folder
        self.deviceID = deviceID
        self.deviceName = deviceName
    }

    // MARK: - Sync folder

    /// The metadata of the vault a folder syncs, or nil if it doesn't sync one yet.
    public static func vaultMetadata(in folder: URL) throws -> (metadata: VaultMetadata, data: Data)? {
        let url = folder.appendingPathComponent(metadataFileName)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let data = try coordinatedRead(url)
        let metadata = try JSONDecoder().decode(VaultMetadata.self, from: data)
        try metadata.validateStructure()
        return (metadata, data)
    }

    /// Where to keep the sync files for a folder the user picked: the folder itself if it
    /// already syncs a vault or is empty, otherwise a subfolder of it. Picking the parent of
    /// an existing sync folder finds that folder.
    public static func resolveFolder(_ chosen: URL) throws -> URL {
        if try vaultMetadata(in: chosen) != nil { return chosen }
        let nested = chosen.appendingPathComponent(subfolderName)
        if try vaultMetadata(in: nested) != nil { return nested }
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: chosen.path)) ?? []
        return contents.allSatisfy { $0.hasPrefix(".") } ? chosen : nested
    }

    // MARK: - Syncing

    /// Runs one sync pass. Call off the main thread: it reads and writes the sync folder.
    /// - Parameters:
    ///   - settings: This Mac's synced settings, each stamped with when it last changed.
    ///   - startNewEpoch: Make this Mac's data replace, rather than merge with, the other
    ///     Macs' data (after restoring a backup).
    public func sync(settings: [String: StampedSetting], startNewEpoch: Bool = false) throws -> SyncResult {
        try prepareFolder()
        let files = try readSnapshots()

        let (changedLocalData, records, epoch) = try dbManager.dbWriter.write { db -> (Bool, VaultRecords, SyncEpoch) in
            var localEpoch = try SyncEpoch.read(db)
            if startNewEpoch {
                localEpoch = SyncEpoch(id: UUID().uuidString, startedAt: Date())
                try localEpoch.write(db)
            }
            let newest = files.remote.map(\.epoch).reduce(localEpoch) { max($0, $1) }
            let local = try VaultRecords.read(db)
            let current = files.remote.filter { $0.epoch == newest }.map(\.records)

            // A newer epoch means another Mac restored a backup: take its data as is.
            let merged = newest > localEpoch ? VaultRecords.merge(current) : VaultRecords.merge([local] + current)
            if newest > localEpoch {
                try newest.write(db)
            }
            guard merged != local else { return (false, local, newest) }
            try merged.apply(over: local, in: db)
            return (true, try VaultRecords.read(db), newest)
        }

        let snapshot = VaultSnapshot(
            schema: Self.snapshotSchema,
            deviceID: deviceID,
            deviceName: deviceName,
            writtenAt: Date(),
            epoch: epoch,
            records: records,
            settings: StampedSetting.merge([settings] + files.remote.map(\.settings))
        )
        if files.own.map({ !$0.hasSameContent(as: snapshot) }) ?? true {
            try Self.coordinatedWrite(try seal(snapshot), to: ownFileURL)
        }

        var devices: [String: SyncedDevice] = [:]
        for file in files.remote where devices[file.deviceID].map({ file.writtenAt > $0.lastSyncedAt }) ?? true {
            devices[file.deviceID] = SyncedDevice(id: file.deviceID, name: file.deviceName, lastSyncedAt: file.writtenAt)
        }
        return SyncResult(
            settings: snapshot.settings,
            changedLocalData: changedLocalData,
            otherDevices: devices.values.sorted { $0.lastSyncedAt > $1.lastSyncedAt },
            unreadableFiles: files.unreadable
        )
    }

    /// Calls `onChange` after each transaction that changes synced data, so the caller can
    /// schedule a sync. Keep the returned object for as long as the observation should run.
    public static func observeChanges(in dbManager: DatabaseManager, onChange: @escaping @Sendable () -> Void) -> SyncChangeObservation {
        let cancellable = DatabaseRegionObservation(tracking: [
            Table("hostGroup"), Table("host"), Table("credential"),
            Table("knownHost"), Table("passwordHistory"), Table("syncTombstone"),
        ])
        .start(in: dbManager.dbWriter, onError: { _ in }, onChange: { _ in onChange() })
        return SyncChangeObservation(cancellable)
    }

    /// Writes the vault metadata the first time, so another Mac can join, and refuses a
    /// folder that syncs a different vault.
    private func prepareFolder() throws {
        try FileManager.default.createDirectory(at: devicesURL, withIntermediateDirectories: true)
        if let existing = try Self.vaultMetadata(in: folder) {
            guard existing.metadata.identifier == vaultID else { throw VaultSyncError.differentVault }
            // Replace a copy with older key-derivation settings once this Mac has upgraded.
            guard existing.metadata.needsUpgrade && !metadata.needsUpgrade else { return }
        }
        try Self.coordinatedWrite(metadataData, to: folder.appendingPathComponent(Self.metadataFileName))
    }

    private func readSnapshots() throws -> (remote: [VaultSnapshot], own: VaultSnapshot?, unreadable: Int) {
        var remote: [VaultSnapshot] = []
        var own: VaultSnapshot?
        var unreadable = 0
        for name in try FileManager.default.contentsOfDirectory(atPath: devicesURL.path) {
            let url = devicesURL.appendingPathComponent(name)
            // iCloud Drive leaves a ".<name>.icloud" placeholder for a file it hasn't downloaded.
            if name.hasPrefix("."), name.hasSuffix(".icloud") {
                let real = devicesURL.appendingPathComponent(String(name.dropFirst().dropLast(".icloud".count)))
                try? FileManager.default.startDownloadingUbiquitousItem(at: real)
                continue
            }
            // Conflict copies ("<id> 2.sshoeboxsync") are read too.
            guard url.pathExtension == Self.fileExtension else { continue }

            let snapshot: VaultSnapshot
            do {
                guard let opened = try open(try Self.coordinatedRead(url)) else { continue }
                snapshot = opened
            } catch VaultSyncError.newerVersion {
                throw VaultSyncError.newerVersion
            } catch {
                unreadable += 1
                continue
            }
            if snapshot.deviceID == deviceID {
                if own.map({ snapshot.writtenAt > $0.writtenAt }) ?? true { own = snapshot }
            } else {
                remote.append(snapshot)
            }
        }
        return (remote, own, unreadable)
    }

    // MARK: - Sealing

    private struct Envelope: Codable {
        var format: Int
        var vaultID: String
        var sealed: Data
    }

    private var sealContext: Data { Data("com.sshoebox.sync.v1:\(vaultID)".utf8) }

    func seal(_ snapshot: VaultSnapshot) throws -> Data {
        let box = try AES.GCM.seal(try JSONEncoder().encode(snapshot), using: syncKey, authenticating: sealContext)
        return try JSONEncoder().encode(Envelope(format: Self.fileFormat, vaultID: vaultID, sealed: box.combined!))
    }

    /// Opens a sync file. Nil if it belongs to another vault; throws if it was altered or
    /// written by a newer SSHoebox (merging it could drop data this version doesn't know).
    func open(_ data: Data) throws -> VaultSnapshot? {
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.format <= Self.fileFormat else { throw VaultSyncError.newerVersion }
        guard envelope.vaultID == vaultID else { return nil }
        let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.sealed), using: syncKey, authenticating: sealContext)
        let snapshot = try JSONDecoder().decode(VaultSnapshot.self, from: plaintext)
        guard snapshot.schema <= Self.snapshotSchema else { throw VaultSyncError.newerVersion }
        return snapshot
    }

    // MARK: - File coordination

    // Coordinated access lets the cloud service's file provider download a file before it's
    // read and see a write as a whole.

    static func coordinatedRead(_ url: URL) throws -> Data {
        var coordinationError: NSError?
        var result: Result<Data, Error> = .failure(CocoaError(.fileReadUnknown))
        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { url in
            result = Result { try Data(contentsOf: url) }
        }
        if let coordinationError { throw coordinationError }
        return try result.get()
    }

    static func coordinatedWrite(_ data: Data, to url: URL) throws {
        var coordinationError: NSError?
        var result: Result<Void, Error> = .failure(CocoaError(.fileWriteUnknown))
        NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &coordinationError) { url in
            result = Result { try data.write(to: url, options: .atomic) }
        }
        if let coordinationError { throw coordinationError }
        try result.get()
    }
}

// MARK: - Snapshot

/// What one Mac writes to its sync file.
struct VaultSnapshot: Codable {
    var schema: Int
    var deviceID: String
    var deviceName: String
    var writtenAt: Date
    var epoch: SyncEpoch
    var records: VaultRecords
    var settings: [String: StampedSetting]

    func hasSameContent(as other: VaultSnapshot) -> Bool {
        schema == other.schema && deviceName == other.deviceName && epoch == other.epoch
            && records == other.records && settings == other.settings
    }
}

/// The history a vault's data belongs to. Restoring a backup starts a new epoch: a Mac that
/// sees a newer epoch replaces its data with that epoch's instead of merging, so the restore
/// isn't undone by the newer edits on other Macs. Every vault starts in the same epoch.
struct SyncEpoch: Codable, Equatable, Comparable {
    var id: String
    var startedAt: Date

    static let initial = SyncEpoch(id: "initial", startedAt: Date(timeIntervalSince1970: 0))
    private static let vaultInfoKey = "syncEpoch"

    static func < (a: SyncEpoch, b: SyncEpoch) -> Bool {
        (a.startedAt, a.id) < (b.startedAt, b.id)
    }

    static func read(_ db: Database) throws -> SyncEpoch {
        guard let json = try String.fetchOne(db, sql: "SELECT value FROM vaultInfo WHERE key = ?", arguments: [vaultInfoKey]) else {
            return .initial
        }
        return try JSONDecoder().decode(SyncEpoch.self, from: Data(json.utf8))
    }

    func write(_ db: Database) throws {
        let json = String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
        try db.execute(sql: "INSERT OR REPLACE INTO vaultInfo (key, value) VALUES (?, ?)", arguments: [Self.vaultInfoKey, json])
    }
}

// MARK: - Settings

/// A synced app setting's value.
public enum SyncedValue: Codable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
}

/// A synced setting with when it was last changed. The latest change wins.
public struct StampedSetting: Codable, Equatable {
    public var value: SyncedValue
    public var modifiedAt: Date

    public init(value: SyncedValue, modifiedAt: Date) {
        self.value = value
        self.modifiedAt = modifiedAt
    }

    static func merge(_ copies: [[String: StampedSetting]]) -> [String: StampedSetting] {
        var merged: [String: StampedSetting] = [:]
        for (key, setting) in copies.joined() {
            if let current = merged[key],
               !VaultRecords.isNewer(setting, setting.modifiedAt, than: current, current.modifiedAt) { continue }
            merged[key] = setting
        }
        return merged
    }
}

// MARK: - Results

/// A running `VaultSyncEngine.observeChanges` observation; stops when cancelled or released.
public final class SyncChangeObservation {
    private let cancellable: AnyDatabaseCancellable

    init(_ cancellable: AnyDatabaseCancellable) {
        self.cancellable = cancellable
    }

    public func cancel() {
        cancellable.cancel()
    }
}

public struct SyncResult {
    /// The merged settings; apply any that differ from this Mac's.
    public var settings: [String: StampedSetting]
    /// The pass added, changed or removed records in the local database.
    public var changedLocalData: Bool
    public var otherDevices: [SyncedDevice]
    /// Sync files that couldn't be opened (damaged, or sealed with another key).
    public var unreadableFiles: Int
}

public struct SyncedDevice: Equatable, Identifiable {
    public var id: String
    public var name: String
    public var lastSyncedAt: Date
}

public enum VaultSyncError: LocalizedError {
    case differentVault
    case newerVersion

    public var errorDescription: String? {
        switch self {
        case .differentVault:
            return "This folder syncs a different vault. Choose another folder, or stop syncing."
        case .newerVersion:
            return "Another Mac syncs with a newer version of SSHoebox. Update SSHoebox on this Mac to keep syncing."
        }
    }
}
