import Foundation
import CryptoKit

public struct CryptoManager {
    
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
    
    /// Derives a key from a password and salt using PBKDF2-HMAC-SHA256.
    /// - Parameters:
    ///   - password: The user's master password.
    ///   - salt: A random salt (recommended 16+ bytes).
    ///   - iterations: Number of iterations (default 100,000).
    ///   - keyByteCount: Desired key length (default 32 for AES-256).
    public static func deriveKey(password: String, salt: Data, iterations: UInt32 = 100_000, keyByteCount: Int = 32) throws -> SymmetricKey {
        guard let passwordData = password.data(using: .utf8) else {
            throw SecurityError.keyDerivationFailed
        }
        
        // PBKDF2 Implementation using CryptoKit
        // DK = T1 || T2 || ... || Tdklen/hlen
        // Ti = F(Password, Salt, c, i)
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
        // U1 = PRF(Password, Salt || INT_32_BE(i))
        // U2 = PRF(Password, U1)
        // ...
        
        var derivedKey = Data()
        var blockIndex: UInt32 = 1
        
        while derivedKey.count < keyByteCount {
            var u = Data()
            u.append(salt)
            u.append(withUnsafeBytes(of: blockIndex.bigEndian) { Data($0) })
            
            var block = Data(HMAC<SHA256>.authenticationCode(for: u, using: SymmetricKey(data: passwordData)))
            var result = block
            
            for _ in 1..<iterations {
                let mac = HMAC<SHA256>.authenticationCode(for: block, using: SymmetricKey(data: passwordData))
                block = Data(mac)
                
                // XOR result with new block
                for (index, byte) in block.enumerated() {
                    result[index] ^= byte
                }
            }
            
            derivedKey.append(result)
            blockIndex += 1
        }
        
        return SymmetricKey(data: derivedKey.prefix(keyByteCount))
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
