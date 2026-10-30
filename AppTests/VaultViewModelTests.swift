import XCTest
import CryptoKit
import SSHoeboxCore
@testable import SSHoeboxApp

/// Exercises VaultViewModel against a throwaway vault folder. The folder is selected through
/// the `vaultDirectoryRaw` default, which in tests lives in the xctest defaults domain, so the
/// user's real vault and settings are never touched. Touch ID is never invoked.
@MainActor
final class VaultViewModelTests: XCTestCase {
    var vaultDir: URL!
    let password = "correct horse battery staple"

    override func setUp() async throws {
        vaultDir = FileManager.default.temporaryDirectory.appendingPathComponent("SSHoeboxTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        UserDefaults.standard.set(vaultDir.path, forKey: "vaultDirectoryRaw")
        UserDefaults.standard.set(false, forKey: "isAgentEnabled")
    }

    override func tearDown() async throws {
        UserDefaults.standard.removeObject(forKey: "vaultDirectoryRaw")
        try? FileManager.default.removeItem(at: vaultDir)
    }

    private var metadataURL: URL { vaultDir.appendingPathComponent("vault_metadata.json") }
    private var dbURL: URL { vaultDir.appendingPathComponent("vault.db") }

    /// Waits for the background key derivation started by unlock/createVault to finish.
    private func settle(_ viewModel: VaultViewModel, file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<200 where viewModel.isUnlocking {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertFalse(viewModel.isUnlocking, "Unlock didn't finish", file: file, line: line)
    }

    private func makeVault() async throws -> VaultViewModel {
        let viewModel = VaultViewModel()
        XCTAssertTrue(viewModel.isNewUser)
        viewModel.createVault(password: password)
        try await settle(viewModel)
        XCTAssertTrue(viewModel.isUnlocked, viewModel.errorMessage ?? "")
        return viewModel
    }

    func testCreateVaultOpensImmediatelyAndEncryptsDatabase() async throws {
        let viewModel = try await makeVault()
        XCTAssertNotNil(viewModel.dbManager)
        XCTAssertNotNil(viewModel.vaultKey)
        XCTAssertNotNil(viewModel.getDependencies())

        let header = try FileHandle(forReadingFrom: dbURL).readData(ofLength: 16)
        XCTAssertNotEqual(header, Data("SQLite format 3\0".utf8), "vault.db must be SQLCipher-encrypted")

        let metadata = try JSONDecoder().decode(VaultMetadata.self, from: Data(contentsOf: metadataURL))
        XCTAssertFalse(metadata.needsUpgrade)
        XCTAssertNil(metadata.salt)
    }

    func testShortMasterPasswordIsRejected() async throws {
        let viewModel = VaultViewModel()
        viewModel.createVault(password: "short")
        try await settle(viewModel)
        XCTAssertFalse(viewModel.isUnlocked)
        XCTAssertNotNil(viewModel.errorMessage)
        XCTAssertFalse(FileManager.default.fileExists(atPath: metadataURL.path))
    }

    func testLockClearsKeyAndEndsSessionsThenUnlockWorks() async throws {
        let viewModel = try await makeVault()
        var lockHookCalls = 0
        viewModel.onLock = { lockHookCalls += 1 }

        viewModel.lock()
        XCTAssertFalse(viewModel.isUnlocked)
        XCTAssertNil(viewModel.vaultKey)
        XCTAssertNil(viewModel.dbManager)
        XCTAssertEqual(lockHookCalls, 1, "Locking must end terminal sessions")

        viewModel.unlock(password: password)
        try await settle(viewModel)
        XCTAssertTrue(viewModel.isUnlocked, viewModel.errorMessage ?? "")
    }

    func testRepeatedWrongPasswordsTriggerLockout() async throws {
        let viewModel = try await makeVault()
        viewModel.lock()

        for _ in 0..<5 {
            viewModel.unlock(password: "wrong password!!")
            try await settle(viewModel)
        }
        XCTAssertFalse(viewModel.isUnlocked)
        XCTAssertTrue(viewModel.errorMessage?.contains("Too many failed attempts") == true, viewModel.errorMessage ?? "nil")

        // Even the right password is refused during the lockout.
        viewModel.unlock(password: password)
        try await settle(viewModel)
        XCTAssertFalse(viewModel.isUnlocked)
    }

    func testLegacyVaultIsUpgradedOnUnlock() async throws {
        // A v1 vault: key = PBKDF2(password, salt, 100k), fields encrypted without context.
        let salt = try CryptoManager.generateSalt()
        let legacyKey = try CryptoManager.deriveKey(password: password, salt: salt,
                                                    iterations: CryptoManager.legacyPBKDF2Iterations)
        let legacy = VaultMetadata(
            salt: salt,
            validation: try CryptoManager.encrypt(Data("SSHOEBOX_VALID".utf8), using: legacyKey),
            version: 1
        )
        try JSONEncoder().encode(legacy).write(to: metadataURL)
        let host = SavedHost(name: try CryptoManager.encryptString("legacy host", using: legacyKey),
                             hostname: try CryptoManager.encryptString("legacy.example.com", using: legacyKey))
        do {
            let db = try DatabaseManager(path: dbURL.path, key: CryptoManager.databaseKey(from: legacyKey))
            try HostRepository(dbManager: db).save(host)
        }

        let viewModel = VaultViewModel()
        XCTAssertFalse(viewModel.isNewUser)
        viewModel.unlock(password: password)
        try await settle(viewModel)
        XCTAssertTrue(viewModel.isUnlocked, viewModel.errorMessage ?? "")
        XCTAssertEqual(viewModel.vaultID, legacy.identifier, "Upgrading must keep the vault's identity")

        let upgraded = try JSONDecoder().decode(VaultMetadata.self, from: Data(contentsOf: metadataURL))
        XCTAssertFalse(upgraded.needsUpgrade)
        XCTAssertNil(upgraded.salt)
        XCTAssertEqual(try upgraded.vaultKey(password: password), legacyKey)

        let migrated = try XCTUnwrap(try HostRepository(dbManager: XCTUnwrap(viewModel.dbManager)).get(id: host.id))
        XCTAssertEqual(Data(base64Encoded: migrated.hostname)?.first, 0x02, "Fields must be re-encrypted with context")
        XCTAssertEqual(migrated.decryptedHostname(using: legacyKey), "legacy.example.com")

        // And it unlocks again through the upgraded metadata.
        viewModel.lock()
        viewModel.unlock(password: password)
        try await settle(viewModel)
        XCTAssertTrue(viewModel.isUnlocked, viewModel.errorMessage ?? "")
    }

    func testMoveVaultIgnoresCurrentFolderAndRefusesOccupiedFolder() async throws {
        let viewModel = try await makeVault()

        try viewModel.moveVault(to: vaultDir)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dbURL.path), "Moving to the same folder must not delete the vault")

        let occupied = vaultDir.appendingPathComponent("occupied")
        try FileManager.default.createDirectory(at: occupied, withIntermediateDirectories: true)
        try Data("other".utf8).write(to: occupied.appendingPathComponent("vault.db"))
        XCTAssertThrowsError(try viewModel.moveVault(to: occupied))
        XCTAssertEqual(try Data(contentsOf: occupied.appendingPathComponent("vault.db")), Data("other".utf8))

        let empty = vaultDir.appendingPathComponent("empty")
        try viewModel.moveVault(to: empty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: empty.appendingPathComponent("vault.db").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: empty.appendingPathComponent("vault_metadata.json").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dbURL.path))
    }

    func testBackupRoundTripRestoresOlderState() async throws {
        let viewModel = try await makeVault()
        let (db, key) = try XCTUnwrap(viewModel.getDependencies())
        let hosts = HostRepository(dbManager: db)
        let kept = try SavedHost.encrypted(name: "kept", hostname: "kept.example.com", port: 22,
                                           protocolType: "ssh", user: "", groupId: nil, using: key)
        try hosts.save(kept)

        let backupData = try BackupManager(dbManager: db).createExportData(
            vaultMetadata: viewModel.currentVaultMetadata(), vaultKey: key)

        let later = try SavedHost.encrypted(name: "later", hostname: "later.example.com", port: 22,
                                            protocolType: "ssh", user: "", groupId: nil, using: key)
        try hosts.save(later)

        let pending = try viewModel.prepareRestore(backupData)
        XCTAssertFalse(pending.needsPassword)
        XCTAssertFalse(pending.isUnauthenticated)
        try await viewModel.authenticateRestore(pending)
        try viewModel.restoreBackup(pending)
        XCTAssertFalse(viewModel.isUnlocked)

        viewModel.unlock(password: password)
        try await settle(viewModel)
        XCTAssertTrue(viewModel.isUnlocked, viewModel.errorMessage ?? "")
        let restored = try HostRepository(dbManager: XCTUnwrap(viewModel.dbManager)).getAll().map(\.id)
        XCTAssertEqual(restored, [kept.id])
    }

    func testBackupFromAnotherVaultNeedsThatVaultsPassword() async throws {
        let first = try await makeVault()
        let (db, key) = try XCTUnwrap(first.getDependencies())
        let backupData = try BackupManager(dbManager: db).createExportData(
            vaultMetadata: first.currentVaultMetadata(), vaultKey: key)
        first.lock()

        // A second vault in another folder.
        let otherDir = vaultDir.appendingPathComponent("second")
        try FileManager.default.createDirectory(at: otherDir, withIntermediateDirectories: true)
        UserDefaults.standard.set(otherDir.path, forKey: "vaultDirectoryRaw")
        let second = VaultViewModel()
        second.createVault(password: "a different master password")
        try await settle(second)
        XCTAssertTrue(second.isUnlocked)

        let pending = try second.prepareRestore(backupData)
        XCTAssertTrue(pending.needsPassword)
        do {
            try await second.authenticateRestore(pending, password: "a different master password")
            XCTFail("The current vault's password must not authenticate another vault's backup")
        } catch {}
        try await second.authenticateRestore(pending, password: password)
    }
}
