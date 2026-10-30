import XCTest
import GRDB
import CryptoKit
@testable import SSHoeboxCore

/// Two "Macs" (in-memory vault databases with the same vault key) syncing through a
/// temporary folder.
final class VaultSyncTests: XCTestCase {
    // Key derivation is slow, so all tests share one vault.
    static var vaultMetadata: Data!
    static var vaultKey: SymmetricKey!

    override class func setUp() {
        let (metadata, key) = try! VaultMetadata.create(password: "correct horse battery staple")
        vaultMetadata = try! JSONEncoder().encode(metadata)
        vaultKey = key
    }

    var folder: URL!
    var macA: DatabaseManager!
    var macB: DatabaseManager!
    var key: SymmetricKey { Self.vaultKey }

    override func setUpWithError() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent("SSHoeboxSyncTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        macA = try DatabaseManager(inMemory: true)
        macB = try DatabaseManager(inMemory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: folder)
    }

    private func engine(_ db: DatabaseManager, _ device: String, metadata: Data? = nil) throws -> VaultSyncEngine {
        try VaultSyncEngine(
            dbManager: db, vaultKey: key, vaultMetadata: metadata ?? Self.vaultMetadata,
            folder: folder, deviceID: device, deviceName: "Mac \(device)"
        )
    }

    @discardableResult
    private func sync(_ db: DatabaseManager, _ device: String, settings: [String: StampedSetting] = [:], newEpoch: Bool = false) throws -> SyncResult {
        try engine(db, device).sync(settings: settings, startNewEpoch: newEpoch)
    }

    private func syncBoth() throws {
        try sync(macA, "A")
        try sync(macB, "B")
        try sync(macA, "A")
    }

    private func ownFile(_ device: String) -> URL {
        folder.appendingPathComponent("devices/\(device).sshoeboxsync")
    }

    private func addHost(_ db: DatabaseManager, name: String = "web", updatedAt: Date = Date()) throws -> SavedHost {
        let host = try SavedHost.encrypted(
            name: name, hostname: "\(name).example.com", port: 22, protocolType: "ssh", user: "deploy",
            groupId: nil, updatedAt: updatedAt, using: key
        )
        try HostRepository(dbManager: db).save(host)
        return host
    }

    // MARK: - Propagation

    func testRecordsAddedOnOneMacReachTheOther() throws {
        let group = HostGroup(name: "Prod")
        try GroupRepository(dbManager: macA).save(group)
        var host = try addHost(macA)
        host.groupId = group.id
        try HostRepository(dbManager: macA).save(host)
        let credential = try CredentialRepository(dbManager: macA).createCredential(
            hostId: host.id, username: "root", type: "password", secret: Data("hunter2".utf8), vaultKey: key
        )

        try sync(macA, "A")
        let result = try sync(macB, "B")

        XCTAssertTrue(result.changedLocalData)
        XCTAssertEqual(result.otherDevices.map(\.name), ["Mac A"])
        // Compare with the stored rows: the database keeps dates to the millisecond.
        XCTAssertEqual(try GroupRepository(dbManager: macB).getAll(), try GroupRepository(dbManager: macA).getAll())
        XCTAssertEqual(try HostRepository(dbManager: macB).get(id: host.id), try HostRepository(dbManager: macA).get(id: host.id))
        let synced = try XCTUnwrap(CredentialRepository(dbManager: macB).getForHost(hostId: host.id).first)
        XCTAssertEqual(try synced.decryptedSecret(using: key), Data("hunter2".utf8))
        XCTAssertEqual(synced, try CredentialRepository(dbManager: macA).getAll().first)
        XCTAssertEqual(synced.id, credential.id)
    }

    func testDeletionReachesTheOtherMacIncludingCascadedRows() throws {
        let host = try addHost(macA)
        _ = try CredentialRepository(dbManager: macA).createCredential(
            hostId: host.id, username: "root", type: "password", secret: Data("x".utf8), vaultKey: key
        )
        try syncBoth()
        XCTAssertEqual(try CredentialRepository(dbManager: macB).getAll().count, 1)

        try HostRepository(dbManager: macA).delete(host)
        try sync(macA, "A")
        try sync(macB, "B")

        XCTAssertNil(try HostRepository(dbManager: macB).get(id: host.id))
        XCTAssertTrue(try CredentialRepository(dbManager: macB).getAll().isEmpty)
        let tombstones = try macB.reader.read { try SyncTombstone.fetchAll($0) }
        XCTAssertEqual(Set(tombstones.map(\.tableName)), ["host", "credential"])
    }

    func testReinsertingADeletedRecordClearsItsTombstone() throws {
        let host = try addHost(macA)
        try HostRepository(dbManager: macA).delete(host)
        try HostRepository(dbManager: macA).save(host)
        XCTAssertEqual(try macA.reader.read { try SyncTombstone.fetchCount($0) }, 0)
    }

    // MARK: - Conflicts

    func testLatestEditWins() throws {
        let host = try addHost(macA, updatedAt: Date(timeIntervalSinceNow: -60))
        try syncBoth()

        var onA = host
        onA.port = 2201
        onA.updatedAt = Date(timeIntervalSinceNow: -30)
        try HostRepository(dbManager: macA).save(onA)
        var onB = host
        onB.port = 2202
        onB.updatedAt = Date(timeIntervalSinceNow: -10)
        try HostRepository(dbManager: macB).save(onB)

        try syncBoth()

        XCTAssertEqual(try HostRepository(dbManager: macA).get(id: host.id)?.port, 2202)
        XCTAssertEqual(try HostRepository(dbManager: macB).get(id: host.id)?.port, 2202)
    }

    func testEditMadeAfterADeletionKeepsTheRecord() throws {
        let host = try addHost(macA, updatedAt: Date(timeIntervalSinceNow: -60))
        try syncBoth()

        try HostRepository(dbManager: macA).delete(host)
        var edited = host
        edited.port = 2222
        edited.updatedAt = Date(timeIntervalSinceNow: 60)
        try HostRepository(dbManager: macB).save(edited)

        try syncBoth()

        XCTAssertEqual(try HostRepository(dbManager: macA).get(id: host.id)?.port, 2222)
        XCTAssertEqual(try HostRepository(dbManager: macB).get(id: host.id)?.port, 2222)
    }

    func testHostInAGroupDeletedElsewhereBecomesUngrouped() throws {
        let group = HostGroup(name: "Old", updatedAt: Date(timeIntervalSinceNow: -60))
        try GroupRepository(dbManager: macA).save(group)
        let host = try addHost(macA, updatedAt: Date(timeIntervalSinceNow: -60))
        try syncBoth()

        try GroupRepository(dbManager: macA).delete(group)
        var moved = host
        moved.groupId = group.id
        moved.updatedAt = Date(timeIntervalSinceNow: 60)
        try HostRepository(dbManager: macB).save(moved)
        let stored = try XCTUnwrap(HostRepository(dbManager: macB).get(id: host.id))

        try syncBoth()

        for mac in [macA!, macB!] {
            XCTAssertTrue(try GroupRepository(dbManager: mac).getAll().isEmpty)
            let synced = try XCTUnwrap(HostRepository(dbManager: mac).get(id: host.id))
            XCTAssertNil(synced.groupId)
            XCTAssertEqual(synced.updatedAt, stored.updatedAt)
        }
    }

    func testLatestConnectionTimeIsKeptWhicheverEditWins() throws {
        let host = try addHost(macA, updatedAt: Date(timeIntervalSinceNow: -60))
        try syncBoth()

        try HostRepository(dbManager: macA).updateLastConnected(hostId: host.id)
        var renamed = host
        renamed.port = 2022
        renamed.updatedAt = Date()
        try HostRepository(dbManager: macB).save(renamed)

        try syncBoth()

        let onB = try XCTUnwrap(HostRepository(dbManager: macB).get(id: host.id))
        XCTAssertEqual(onB.port, 2022)
        XCTAssertNotNil(onB.lastConnectedAt)
        XCTAssertEqual(try HostRepository(dbManager: macA).get(id: host.id), onB)
    }

    func testConflictingTrustedKeysKeepTheOneTrustedFirst() throws {
        let first = KnownHost(hostname: "git.example.com", port: 22, keyType: "ssh-ed25519",
                              keyFingerprint: "SHA256:first", openSSHPublicKey: "ssh-ed25519 AAAAfirst",
                              firstSeenAt: Date(timeIntervalSinceNow: -60))
        let second = KnownHost(hostname: "git.example.com", port: 22, keyType: "ssh-ed25519",
                               keyFingerprint: "SHA256:second", openSSHPublicKey: "ssh-ed25519 AAAAsecond",
                               firstSeenAt: Date(timeIntervalSinceNow: -30))
        try KnownHostRepository(dbManager: macA).save(first)
        try KnownHostRepository(dbManager: macB).save(second)

        try syncBoth()

        for mac in [macA!, macB!] {
            XCTAssertEqual(try KnownHostRepository(dbManager: mac).getAll().map(\.keyFingerprint), ["SHA256:first"])
        }
    }

    func testLatestSettingWins() throws {
        let old = StampedSetting(value: .string("dracula"), modifiedAt: Date(timeIntervalSinceNow: -60))
        let new = StampedSetting(value: .string("solarized"), modifiedAt: Date(timeIntervalSinceNow: -10))
        let size = StampedSetting(value: .double(15), modifiedAt: Date(timeIntervalSinceNow: -5))

        try sync(macA, "A", settings: ["selectedThemeId": new])
        let result = try sync(macB, "B", settings: ["selectedThemeId": old, "terminalFontSize": size])

        XCTAssertEqual(result.settings, ["selectedThemeId": new, "terminalFontSize": size])
        XCTAssertEqual(try sync(macA, "A", settings: ["selectedThemeId": new]).settings, result.settings)
    }

    // MARK: - Restore

    func testNewEpochReplacesTheOtherMacsData() throws {
        let kept = try addHost(macA, name: "kept", updatedAt: Date(timeIntervalSinceNow: -60))
        try syncBoth()
        // Added on B after the backup that A then restores
        let added = try addHost(macB, name: "added")
        try sync(macB, "B")

        try sync(macA, "A", newEpoch: true)
        let result = try sync(macB, "B")

        XCTAssertTrue(result.changedLocalData)
        XCTAssertEqual(try HostRepository(dbManager: macB).getAll().map(\.id), [kept.id])
        XCTAssertNil(try HostRepository(dbManager: macA).get(id: added.id))
        // Later edits merge as usual within the new epoch.
        let afterRestore = try addHost(macB, name: "after")
        try sync(macB, "B")
        try sync(macA, "A")
        XCTAssertNotNil(try HostRepository(dbManager: macA).get(id: afterRestore.id))
    }

    // MARK: - Files

    func testSyncWithNothingNewLeavesTheFileAlone() throws {
        _ = try addHost(macA)
        try syncBoth()
        let before = try Data(contentsOf: ownFile("A"))

        let result = try sync(macA, "A")

        XCTAssertFalse(result.changedLocalData)
        XCTAssertEqual(try Data(contentsOf: ownFile("A")), before)
    }

    func testSyncFilesRevealNothing() throws {
        try KnownHostRepository(dbManager: macA).save(KnownHost(
            hostname: "bastion.internal.example", port: 22, keyType: "ssh-ed25519",
            keyFingerprint: "SHA256:abc", openSSHPublicKey: "ssh-ed25519 AAAA"
        ))
        try sync(macA, "A", settings: ["selectedThemeId": StampedSetting(value: .string("dracula"), modifiedAt: Date())])

        let file = String(decoding: try Data(contentsOf: ownFile("A")), as: UTF8.self)
        XCTAssertFalse(file.contains("bastion"))
        XCTAssertFalse(file.contains("dracula"))
    }

    func testAlteredFileIsIgnored() throws {
        _ = try addHost(macA)
        try sync(macA, "A")
        var envelope = try JSONSerialization.jsonObject(with: Data(contentsOf: ownFile("A"))) as! [String: Any]
        var sealed = try XCTUnwrap(Data(base64Encoded: envelope["sealed"] as! String))
        sealed[sealed.count - 1] ^= 0x01
        envelope["sealed"] = sealed.base64EncodedString()
        try JSONSerialization.data(withJSONObject: envelope).write(to: ownFile("A"))

        let result = try sync(macB, "B")

        XCTAssertEqual(result.unreadableFiles, 1)
        XCTAssertTrue(try HostRepository(dbManager: macB).getAll().isEmpty)
    }

    func testConflictCopiesAreMerged() throws {
        let host = try addHost(macA)
        try sync(macA, "A")
        try FileManager.default.moveItem(at: ownFile("A"), to: folder.appendingPathComponent("devices/A 2.sshoeboxsync"))

        try sync(macB, "B")

        XCTAssertNotNil(try HostRepository(dbManager: macB).get(id: host.id))
    }

    func testFolderOfAnotherVaultIsRefused() throws {
        let (other, otherKey) = try VaultMetadata.create(password: "another vault's password")
        let otherEngine = try VaultSyncEngine(
            dbManager: macB, vaultKey: otherKey, vaultMetadata: try JSONEncoder().encode(other),
            folder: folder, deviceID: "B", deviceName: "Mac B"
        )
        try sync(macA, "A")

        XCTAssertThrowsError(try otherEngine.sync(settings: [:])) { error in
            guard case VaultSyncError.differentVault = error else { return XCTFail("\(error)") }
        }
    }

    func testFileFromANewerVersionStopsSync() throws {
        let engineA = try engine(macA, "A")
        var snapshot = VaultSnapshot(schema: VaultSyncEngine.snapshotSchema + 1, deviceID: "A", deviceName: "Mac A",
                                     writtenAt: Date(), epoch: .initial, records: VaultRecords(), settings: [:])
        snapshot.records.groups = [HostGroup(name: "From the future")]
        try sync(macB, "B")
        try engineA.seal(snapshot).write(to: ownFile("A"))

        XCTAssertThrowsError(try sync(macB, "B")) { error in
            guard case VaultSyncError.newerVersion = error else { return XCTFail("\(error)") }
        }
        XCTAssertTrue(try GroupRepository(dbManager: macB).getAll().isEmpty)
    }

    func testResolveFolder() throws {
        XCTAssertEqual(try VaultSyncEngine.resolveFolder(folder).path, folder.path)

        try Data().write(to: folder.appendingPathComponent("notes.txt"))
        let nested = folder.appendingPathComponent(VaultSyncEngine.subfolderName)
        XCTAssertEqual(try VaultSyncEngine.resolveFolder(folder).path, nested.path)

        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try VaultSyncEngine(dbManager: macA, vaultKey: key, vaultMetadata: Self.vaultMetadata,
                            folder: nested, deviceID: "A", deviceName: "Mac A").sync(settings: [:])
        XCTAssertEqual(try VaultSyncEngine.resolveFolder(folder).path, nested.path)
        XCTAssertEqual(try VaultSyncEngine.resolveFolder(nested).path, nested.path)
    }
}
