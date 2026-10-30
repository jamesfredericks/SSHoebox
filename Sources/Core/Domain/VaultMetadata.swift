import Foundation
import CryptoKit

/// Contents of the portable `vault_metadata.json` sidecar.
///
/// - v0/v1 (legacy): the vault key *is* PBKDF2(password, `salt`, 100k). `validation` is an
///   AES-GCM sentinel encrypted with it.
/// - v2: the vault key is a random 256-bit key, wrapped (AES-GCM) by a key-encryption key
///   derived with the parameters in `kdf`. The vault key never changes, so the KDF can be
///   strengthened (or the password changed) by re-wrapping it, without re-encrypting the vault.
///   Upgraded vaults drop the legacy `salt`, so a copy of the metadata no longer lets anyone
///   test passwords at the old, cheaper iteration count.
public struct VaultMetadata: Codable, Equatable {
    /// Legacy (v0/v1) PBKDF2 salt of the vault key itself. Nil from v2 onward.
    public let salt: Data?
    public let validation: Data
    public var version: Int? // Optional for backward compatibility. Nil means 0 (Legacy).
    /// v2: how the key-encryption key is derived from the master password.
    public var kdf: KDFParameters?
    /// v2: the vault key, AES-GCM sealed with the key-encryption key.
    public var wrappedKey: Data?
    /// v2: stable vault identifier (carried over from the legacy salt-derived one on upgrade).
    public var id: String?

    public struct KDFParameters: Codable, Equatable {
        public var algorithm: String
        public var iterations: UInt32
        public var salt: Data

        public static let pbkdf2SHA256 = "pbkdf2-sha256"
    }

    public static let currentVersion = 2
    private static let validationSentinel = "SSHOEBOX_VALID"
    private static let wrapContext = "com.sshoebox.vault-key.v2"
    /// Upper bound on accepted iterations, so tampered metadata can't hang unlock.
    private static let maxIterations: UInt32 = 20_000_000

    /// Stable, non-secret identifier for this vault, used to scope per-vault state such as
    /// the biometric keychain item.
    public var identifier: String {
        if let id { return id }
        return SHA256.hash(data: salt ?? Data()).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    /// True for metadata written before key wrapping; upgraded on the next password unlock.
    public var needsUpgrade: Bool { wrappedKey == nil }

    public init(salt: Data, validation: Data, version: Int?) {
        self.salt = salt
        self.validation = validation
        self.version = version
    }

    private init(validation: Data, kdf: KDFParameters, wrappedKey: Data, id: String) {
        self.salt = nil
        self.validation = validation
        self.version = Self.currentVersion
        self.kdf = kdf
        self.wrappedKey = wrappedKey
        self.id = id
    }

    // MARK: - Creating and unlocking

    /// Creates metadata for a new vault with a random vault key.
    public static func create(password: String) throws -> (metadata: VaultMetadata, vaultKey: SymmetricKey) {
        let vaultKey = CryptoManager.generateRandomKey()
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let metadata = try wrapping(vaultKey, password: password, id: id)
        return (metadata, vaultKey)
    }

    /// Returns the vault key for `password`, or nil if the password is wrong.
    /// Throws if the metadata itself is malformed. Slow by design: call off the main thread.
    public func vaultKey(password: String) throws -> SymmetricKey? {
        if let wrappedKey {
            guard let kdf else { throw VaultMetadataError.malformed }
            let kek = try Self.keyEncryptionKey(password: password, kdf: kdf)
            guard let keyData = try? CryptoManager.decrypt(wrappedKey, using: kek, context: Self.wrapContext),
                  keyData.count == 32 else { return nil }
            let key = SymmetricKey(data: keyData)
            return isValid(key) ? key : nil
        }
        guard let salt else { throw VaultMetadataError.malformed }
        let key = try CryptoManager.deriveKey(password: password, salt: salt, iterations: CryptoManager.legacyPBKDF2Iterations)
        return isValid(key) ? key : nil
    }

    /// Re-wraps the vault key under `password` with current KDF parameters, keeping the
    /// vault identifier. Used to upgrade legacy metadata (and could change the password).
    public func rewrapped(vaultKey: SymmetricKey, password: String) throws -> VaultMetadata {
        guard isValid(vaultKey) else { throw VaultMetadataError.keyMismatch }
        return try Self.wrapping(vaultKey, password: password, id: identifier, validation: validation)
    }

    /// Whether `key` is this vault's key.
    public func isValid(_ key: SymmetricKey) -> Bool {
        guard let decrypted = try? CryptoManager.decrypt(validation, using: key) else { return false }
        return String(data: decrypted, encoding: .utf8) == Self.validationSentinel
    }

    /// Checks the metadata is well formed before it's trusted (e.g. from a backup).
    public func validateStructure() throws {
        if let wrappedKey {
            guard let kdf, !wrappedKey.isEmpty, id?.isEmpty == false else { throw VaultMetadataError.malformed }
            try Self.check(kdf)
        } else {
            guard let salt, !salt.isEmpty else { throw VaultMetadataError.malformed }
        }
    }

    // MARK: - Private

    private static func wrapping(_ vaultKey: SymmetricKey, password: String, id: String, validation: Data? = nil) throws -> VaultMetadata {
        let kdf = KDFParameters(
            algorithm: KDFParameters.pbkdf2SHA256,
            iterations: CryptoManager.currentPBKDF2Iterations,
            salt: try CryptoManager.generateSalt()
        )
        let kek = try keyEncryptionKey(password: password, kdf: kdf)
        let wrapped = try vaultKey.withUnsafeBytes {
            try CryptoManager.encrypt(Data($0), using: kek, context: wrapContext)
        }
        let validation = try validation ?? CryptoManager.encrypt(Data(validationSentinel.utf8), using: vaultKey)
        return VaultMetadata(validation: validation, kdf: kdf, wrappedKey: wrapped, id: id)
    }

    private static func keyEncryptionKey(password: String, kdf: KDFParameters) throws -> SymmetricKey {
        try check(kdf)
        return try CryptoManager.deriveKey(password: password, salt: kdf.salt, iterations: kdf.iterations)
    }

    private static func check(_ kdf: KDFParameters) throws {
        guard kdf.algorithm == KDFParameters.pbkdf2SHA256,
              kdf.iterations >= CryptoManager.legacyPBKDF2Iterations,
              kdf.iterations <= maxIterations,
              kdf.salt.count >= 16 else {
            throw VaultMetadataError.unsupportedKDF
        }
    }
}

public enum VaultMetadataError: LocalizedError {
    case malformed
    case unsupportedKDF
    case keyMismatch

    public var errorDescription: String? {
        switch self {
        case .malformed: return "The vault metadata (vault_metadata.json) is damaged."
        case .unsupportedKDF: return "The vault metadata uses unsupported key-derivation settings."
        case .keyMismatch: return "The key does not belong to this vault."
        }
    }
}
