import XCTest
import CryptoKit
@testable import SSHoeboxCore

final class CryptoTests: XCTestCase {
    
    func testEncryptionDecryption() throws {
        let key = CryptoManager.generateRandomKey()
        let originalData = "Hello, World!".data(using: .utf8)!
        
        let encrypted = try CryptoManager.encrypt(originalData, using: key)
        let decrypted = try CryptoManager.decrypt(encrypted, using: key)
        
        XCTAssertEqual(originalData, decrypted, "Decrypted data should match original")
    }
    
    func testDecryptionFailWithWrongKey() throws {
        let key1 = CryptoManager.generateRandomKey()
        let key2 = CryptoManager.generateRandomKey()
        let originalData = "Secret".data(using: .utf8)!
        
        let encrypted = try CryptoManager.encrypt(originalData, using: key1)
        
        XCTAssertThrowsError(try CryptoManager.decrypt(encrypted, using: key2)) { error in
            guard let securityError = error as? SecurityError else {
                XCTFail("Expected SecurityError, got \(error)")
                return
            }
            XCTAssertEqual(securityError.localizedDescription, SecurityError.decryptionFailed.localizedDescription) 
            // Note: In practice Equatable should be better but localizedDescription is a quick check
        }
    }
    
    func testKeyDerivationConsistency() throws {
        let password = "MySecurePassword123"
        let salt = try CryptoManager.generateSalt()
        
        let key1 = try CryptoManager.deriveKey(password: password, salt: salt)
        let key2 = try CryptoManager.deriveKey(password: password, salt: salt)
        
        XCTAssertEqual(key1.withUnsafeBytes { Data($0) }, key2.withUnsafeBytes { Data($0) }, "Deriving key twice with same inputs should yield same key")
    }
    
    func testKeyDerivationUniqueness() throws {
        let password = "MySecurePassword123"
        let salt1 = try CryptoManager.generateSalt()
        let salt2 = try CryptoManager.generateSalt()
        
        let key1 = try CryptoManager.deriveKey(password: password, salt: salt1)
        let key2 = try CryptoManager.deriveKey(password: password, salt: salt2)
        
        XCTAssertNotEqual(key1.withUnsafeBytes { Data($0) }, key2.withUnsafeBytes { Data($0) }, "Different salts should yield different keys")
    }
}
