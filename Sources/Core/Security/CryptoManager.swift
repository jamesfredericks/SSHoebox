import Foundation
import CryptoKit
import CommonCrypto

public struct CryptoManager {

    /// PBKDF2 iterations used by vaults created before key wrapping (metadata v0/v1).
    public static let legacyPBKDF2Iterations: UInt32 = 100_000
    /// PBKDF2-HMAC-SHA256 iterations for the key-encryption key of new and upgraded vaults
    /// (OWASP 2023 guidance).
    public static let currentPBKDF2Iterations: UInt32 = 600_000

    /// First byte of a field ciphertext that is bound to its context (see `encrypt(_:using:context:)`).
    /// Legacy ciphertexts have no prefix and start directly with the random nonce.
    static let contextBoundFormat: UInt8 = 0x02

    // MARK: - AES-GCM Encryption

    /// Encrypts data using AES-GCM with the provided SymmetricKey.
    /// Returns the sealed box combined (nonce + ciphertext + tag).
    public static func encrypt(_ data: Data, using key: SymmetricKey) throws -> Data {
        do {
            let sealedBox = try AES.GCM.seal(data, using: key)
            return sealedBox.combined!
        } catch {
            throw SecurityError.encryptionFailed
        }
    }

    /// Decrypts a combined data blob (nonce + ciphertext + tag) using AES-GCM.
    public static func decrypt(_ combinedData: Data, using key: SymmetricKey) throws -> Data {
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: combinedData)
            return try AES.GCM.open(sealedBox, using: key)
        } catch {
            throw SecurityError.decryptionFailed
        }
    }

    /// Encrypts a vault field, authenticating `context` (which names the table, column and
    /// row) as associated data. A ciphertext then only decrypts in the place it was written,
    /// so encrypted values can't be swapped between rows or columns.
    /// Format: `0x02 || nonce || ciphertext || tag`.
    public static func encrypt(_ data: Data, using key: SymmetricKey, context: String) throws -> Data {
        do {
            let sealedBox = try AES.GCM.seal(data, using: key, authenticating: Data(context.utf8))
            return Data([contextBoundFormat]) + sealedBox.combined!
        } catch {
            throw SecurityError.encryptionFailed
        }
    }

    /// Decrypts a vault field written by `encrypt(_:using:context:)`. Fields written by older
    /// versions (no prefix, no associated data) are still accepted; unlocking re-encrypts them
    /// in the new format (see `FieldEncryptionMigration`).
    public static func decrypt(_ data: Data, using key: SymmetricKey, context: String) throws -> Data {
        if data.first == contextBoundFormat,
           let sealedBox = try? AES.GCM.SealedBox(combined: data.dropFirst()),
           let plaintext = try? AES.GCM.open(sealedBox, using: key, authenticating: Data(context.utf8)) {
            return plaintext
        }
        return try decrypt(data, using: key)
    }

    /// Encrypts a string and returns a Base64 encoded string.
    public static func encryptString(_ value: String, using key: SymmetricKey) throws -> String {
        guard let data = value.data(using: .utf8) else { throw SecurityError.encryptionFailed }
        let encrypted = try encrypt(data, using: key)
        return encrypted.base64EncodedString()
    }

    /// Decrypts a Base64 encoded string.
    public static func decryptString(_ base64: String, using key: SymmetricKey) throws -> String {
        guard let data = Data(base64Encoded: base64) else { throw SecurityError.decryptionFailed }
        let decrypted = try decrypt(data, using: key)
        guard let string = String(data: decrypted, encoding: .utf8) else { throw SecurityError.decryptionFailed }
        return string
    }

    /// Context-bound variant of `encryptString(_:using:)`.
    public static func encryptString(_ value: String, using key: SymmetricKey, context: String) throws -> String {
        try encrypt(Data(value.utf8), using: key, context: context).base64EncodedString()
    }

    /// Context-bound variant of `decryptString(_:using:)`; also accepts legacy ciphertexts.
    public static func decryptString(_ base64: String, using key: SymmetricKey, context: String) throws -> String {
        guard let data = Data(base64Encoded: base64) else { throw SecurityError.decryptionFailed }
        let decrypted = try decrypt(data, using: key, context: context)
        guard let string = String(data: decrypted, encoding: .utf8) else { throw SecurityError.decryptionFailed }
        return string
    }

    /// Derives the raw 32-byte SQLCipher database key from the vault key.
    /// HKDF with a distinct `info` label keeps the database key independent of the
    /// key used for field-level AES-GCM encryption.
    public static func databaseKey(from vaultKey: SymmetricKey) -> Data {
        subkey(from: vaultKey, label: "com.sshoebox.sqlcipher.v1").withUnsafeBytes { Data($0) }
    }

    /// Derives an independent 256-bit subkey of the vault key for a single purpose.
    public static func subkey(from vaultKey: SymmetricKey, label: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: vaultKey,
            info: Data(label.utf8),
            outputByteCount: 32
        )
    }

    /// Derives a key from a password and salt using PBKDF2-HMAC-SHA256 (CommonCrypto).
    /// This is slow by design; call it off the main thread.
    /// - Parameters:
    ///   - password: The user's master password.
    ///   - salt: A random salt (recommended 16+ bytes).
    ///   - iterations: Number of iterations; see `legacyPBKDF2Iterations` and `currentPBKDF2Iterations`.
    ///   - keyByteCount: Desired key length (default 32 for AES-256).
    public static func deriveKey(password: String, salt: Data, iterations: UInt32, keyByteCount: Int = 32) throws -> SymmetricKey {
        guard iterations > 0, keyByteCount > 0 else { throw SecurityError.keyDerivationFailed }
        let passwordBytes = Array(password.utf8)
        var derived = [UInt8](repeating: 0, count: keyByteCount)
        defer { derived.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }

        let status = salt.withUnsafeBytes { saltBuffer in
            passwordBytes.withUnsafeBufferPointer { passwordBuffer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBuffer.baseAddress.map { UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self) },
                    passwordBuffer.count,
                    saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                    saltBuffer.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    &derived,
                    derived.count
                )
            }
        }
        guard status == kCCSuccess else { throw SecurityError.keyDerivationFailed }
        return SymmetricKey(data: derived)
    }

    // MARK: - Utilities

    /// Generates a random salt of specified size.
    public static func generateSalt(size: Int = 32) throws -> Data {
        var salt = Data(count: size)
        let result = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw SecurityError.rngFailed
        }
        return salt
    }

    /// Generates a random 256-bit key.
    public static func generateRandomKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }
}
