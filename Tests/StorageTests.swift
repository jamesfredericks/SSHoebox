import XCTest
import GRDB
import CryptoKit
@testable import SSHoeboxCore

final class StorageTests: XCTestCase {
    
    var dbManager: DatabaseManager!
    var hostRepo: HostRepository!
    var credentialRepo: CredentialRepository!
    
    override func setUpWithError() throws {
        dbManager = try DatabaseManager(inMemory: true)
        hostRepo = HostRepository(dbManager: dbManager)
        credentialRepo = CredentialRepository(dbManager: dbManager)
    }
    
    func testHostCRUD() throws {
        let host = SavedHost(name: "Test Server", hostname: "192.168.1.1")
        try hostRepo.save(host)
        
        let fetched = try hostRepo.get(id: host.id)
        XCTAssertNotNil(fetched)
        XCTAssertEqual(fetched?.name, "Test Server")
        
        try hostRepo.delete(host)
        let deleted = try hostRepo.get(id: host.id)
        XCTAssertNil(deleted)
    }
    
    func testCredentialEncryption() throws {
        let host = SavedHost(name: "Test Server", hostname: "example.com")
        try hostRepo.save(host)
        
        let vaultKey = CryptoManager.generateRandomKey()
        let secret = "supersecretpassword".data(using: .utf8)!
        
        // Create and Encrypt
        let credential = try credentialRepo.createCredential(hostId: host.id, username: "admin", type: "password", secret: secret, vaultKey: vaultKey)
        
        // Fetch
        let fetchedCreds = try credentialRepo.getForHost(hostId: host.id)
        XCTAssertEqual(fetchedCreds.count, 1)
        
        // Decrypt
        let decrypted = try credentialRepo.decryptSecret(for: fetchedCreds.first!, vaultKey: vaultKey)
        XCTAssertEqual(decrypted, secret)
    }
}
