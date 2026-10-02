import XCTest
import GRDB
import CryptoKit
@testable import SSHoeboxCore

final class KeyDerivationTests: XCTestCase {
    private func hex(_ key: SymmetricKey) -> String {
        key.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
    }

    /// PBKDF2-HMAC-SHA256 test vectors (RFC 7914 §11 / widely published). The previous
    /// hand-written implementation was standard PBKDF2, so legacy vault keys still match.
    func testPBKDF2MatchesKnownVectors() throws {
        let salt = Data("salt".utf8)
        XCTAssertEqual(hex(try CryptoManager.deriveKey(password: "password", salt: salt, iterations: 1)),
                       "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        XCTAssertEqual(hex(try CryptoManager.deriveKey(password: "password", salt: salt, iterations: 2)),
                       "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        XCTAssertEqual(hex(try CryptoManager.deriveKey(password: "password", salt: salt, iterations: 4096)),
                       "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
    }
}

final class VaultKeyWrappingTests: XCTestCase {
    func testNewVaultUnlocksOnlyWithItsPassword() throws {
        let (metadata, key) = try VaultMetadata.create(password: "correct horse battery")
        XCTAssertEqual(metadata.version, VaultMetadata.currentVersion)
        XCTAssertNil(metadata.salt)
        XCTAssertEqual(metadata.kdf?.iterations, CryptoManager.currentPBKDF2Iterations)
        XCTAssertFalse(metadata.needsUpgrade)

        let unlocked = try XCTUnwrap(try metadata.vaultKey(password: "correct horse battery"))
        XCTAssertEqual(unlocked, key)
        XCTAssertNil(try metadata.vaultKey(password: "wrong password"))
    }

    func testMetadataSurvivesJSONRoundTrip() throws {
        let (metadata, key) = try VaultMetadata.create(password: "round trip password")
        let decoded = try JSONDecoder().decode(VaultMetadata.self, from: JSONEncoder().encode(metadata))
        XCTAssertEqual(decoded, metadata)
        XCTAssertEqual(try decoded.vaultKey(password: "round trip password"), key)
    }

    /// A legacy vault's key is PBKDF2(password, salt, 100k). Upgrading wraps that same key,
    /// so nothing in the database needs re-encrypting, and drops the legacy salt.
    func testLegacyVaultUpgradeKeepsKeyAndIdentifier() throws {
        let salt = try CryptoManager.generateSalt()
        let legacyKey = try CryptoManager.deriveKey(password: "legacy password", salt: salt,
                                                    iterations: CryptoManager.legacyPBKDF2Iterations)
        let validation = try CryptoManager.encrypt(Data("SSHOEBOX_VALID".utf8), using: legacyKey)
        let legacy = VaultMetadata(salt: salt, validation: validation, version: 1)
        XCTAssertTrue(legacy.needsUpgrade)
        XCTAssertEqual(try legacy.vaultKey(password: "legacy password"), legacyKey)
        XCTAssertNil(try legacy.vaultKey(password: "nope"))

        let upgraded = try legacy.rewrapped(vaultKey: legacyKey, password: "legacy password")
        XCTAssertNil(upgraded.salt, "The upgraded metadata must not allow the old, cheaper KDF")
        XCTAssertEqual(upgraded.identifier, legacy.identifier, "Touch ID enrollment is keyed by identifier")
        XCTAssertEqual(try upgraded.vaultKey(password: "legacy password"), legacyKey)
        XCTAssertNil(try upgraded.vaultKey(password: "nope"))
    }

    func testRewrapRejectsForeignKey() throws {
        let (metadata, _) = try VaultMetadata.create(password: "first vault password")
        XCTAssertThrowsError(try metadata.rewrapped(vaultKey: CryptoManager.generateRandomKey(), password: "x"))
    }

    func testTamperedKDFParametersAreRejected() throws {
        var (metadata, _) = try VaultMetadata.create(password: "kdf tamper password")
        metadata.kdf?.iterations = 1
        XCTAssertThrowsError(try metadata.vaultKey(password: "kdf tamper password"))
        XCTAssertThrowsError(try metadata.validateStructure())

        metadata.kdf?.iterations = UInt32.max
        XCTAssertThrowsError(try metadata.vaultKey(password: "kdf tamper password"), "Must not hang on absurd iteration counts")
    }
}

final class FieldEncryptionTests: XCTestCase {
    var dbManager: DatabaseManager!
    let key = CryptoManager.generateRandomKey()

    override func setUpWithError() throws {
        dbManager = try DatabaseManager(inMemory: true)
    }

    func testCiphertextIsBoundToItsRowAndColumn() throws {
        let a = try SavedHost.encrypted(name: "prod", hostname: "prod.example.com", port: 22,
                                        protocolType: "ssh", user: "root", groupId: nil, using: key)
        var b = try SavedHost.encrypted(name: "staging", hostname: "staging.example.com", port: 22,
                                        protocolType: "ssh", user: "deploy", groupId: nil, using: key)
        XCTAssertEqual(a.decryptedHostname(using: key), "prod.example.com")

        // Moving prod's hostname ciphertext into another row (or column) must not decrypt there.
        b.hostname = a.hostname
        XCTAssertNotEqual(b.decryptedHostname(using: key), "prod.example.com")
        b.name = a.hostname
        XCTAssertNotEqual(b.decryptedName(using: key), "prod.example.com")
    }

    func testCredentialSecretIsBoundToItsRow() throws {
        let host = try SavedHost.encrypted(name: "h", hostname: "h", port: 22, protocolType: "ssh",
                                           user: "", groupId: nil, using: key)
        try HostRepository(dbManager: dbManager).save(host)
        let repo = CredentialRepository(dbManager: dbManager)
        let first = try repo.createCredential(hostId: host.id, username: "alice", type: "password",
                                              secret: Data("first".utf8), vaultKey: key)
        var second = try repo.createCredential(hostId: host.id, username: "bob", type: "password",
                                               secret: Data("second".utf8), vaultKey: key)

        XCTAssertEqual(try repo.decryptSecret(for: first, vaultKey: key), Data("first".utf8))
        XCTAssertNotEqual(first.username, "alice", "Usernames must be stored encrypted")
        XCTAssertEqual(first.decryptedUsername(using: key), "alice")

        second.encryptedBlob = first.encryptedBlob
        XCTAssertThrowsError(try repo.decryptSecret(for: second, vaultKey: key))
    }

    func testLegacyCiphertextsStillDecrypt() throws {
        let legacy = SavedHost(name: try CryptoManager.encryptString("old", using: key),
                               hostname: try CryptoManager.encryptString("old.example.com", using: key))
        XCTAssertEqual(legacy.decryptedName(using: key), "old")
        XCTAssertEqual(legacy.decryptedHostname(using: key), "old.example.com")
    }

    func testMigrationReencryptsLegacyAndPlaintextFields() throws {
        // A v0 host (plaintext), a v1 host (legacy ciphertext), and a plaintext credential username
        // as written by Add Host before this fix.
        let plaintextHost = SavedHost(name: "plain", hostname: "plain.example.com", user: "root")
        let legacyHost = SavedHost(name: try CryptoManager.encryptString("legacy", using: key),
                                   hostname: try CryptoManager.encryptString("legacy.example.com", using: key),
                                   user: try CryptoManager.encryptString("admin", using: key))
        let hosts = HostRepository(dbManager: dbManager)
        try hosts.save(plaintextHost)
        try hosts.save(legacyHost)
        let credential = Credential(hostId: legacyHost.id, username: "deploy", type: "password",
                                    encryptedBlob: try CryptoManager.encrypt(Data("s3cret".utf8), using: key))
        try CredentialRepository(dbManager: dbManager).save(credential)
        let history = PasswordHistory(credentialId: credential.id,
                                      encryptedBlob: try CryptoManager.encrypt(Data("old".utf8), using: key))
        try dbManager.dbWriter.write { try history.insert($0) }

        XCTAssertTrue(try FieldEncryptionMigration.isNeeded(dbManager))
        try FieldEncryptionMigration.run(dbManager, vaultKey: key)
        XCTAssertFalse(try FieldEncryptionMigration.isNeeded(dbManager))

        let migratedPlain = try XCTUnwrap(try hosts.get(id: plaintextHost.id))
        XCTAssertNotEqual(migratedPlain.name, "plain")
        XCTAssertEqual(migratedPlain.decryptedName(using: key), "plain")
        XCTAssertEqual(migratedPlain.decryptedHostname(using: key), "plain.example.com")
        XCTAssertEqual(migratedPlain.decryptedUser(using: key), "root")

        let migratedLegacy = try XCTUnwrap(try hosts.get(id: legacyHost.id))
        XCTAssertEqual(Data(base64Encoded: migratedLegacy.hostname)?.first, CryptoManager.contextBoundFormat)
        XCTAssertEqual(migratedLegacy.decryptedHostname(using: key), "legacy.example.com")

        let migratedCredential = try XCTUnwrap(try CredentialRepository(dbManager: dbManager).getAll().first)
        XCTAssertNotEqual(migratedCredential.username, "deploy")
        XCTAssertEqual(migratedCredential.decryptedUsername(using: key), "deploy")
        XCTAssertEqual(migratedCredential.encryptedBlob.first, CryptoManager.contextBoundFormat)
        XCTAssertEqual(try migratedCredential.decryptedSecret(using: key), Data("s3cret".utf8))

        let migratedHistory = try XCTUnwrap(try PasswordHistoryRepository(dbManager: dbManager).getAll(for: credential.id).first)
        XCTAssertEqual(try migratedHistory.decryptedSecret(using: key), Data("old".utf8))
    }

    func testMigrationLeavesUndecryptableCiphertextAlone() throws {
        let foreign = try CryptoManager.encryptString("someone else's", using: CryptoManager.generateRandomKey())
        let host = SavedHost(name: foreign, hostname: "h.example.com")
        try HostRepository(dbManager: dbManager).save(host)

        try FieldEncryptionMigration.run(dbManager, vaultKey: key)

        let migrated = try XCTUnwrap(try HostRepository(dbManager: dbManager).get(id: host.id))
        XCTAssertEqual(migrated.name, foreign, "A ciphertext that won't decrypt must not be encrypted again")
    }
}
