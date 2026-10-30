import XCTest
@testable import SSHoeboxCore

final class HostKeyTrustTests: XCTestCase {
    // Throwaway public keys generated with ssh-keygen for these tests.
    let rsaKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD3sGNacT5g1rtERwKgihKGedjE/vleamhm9yfS/Mlt5e4xPVAHtnDMc7Z3JMt2liLHcIfqsvlshXjVyrnnyxutQbRBXe7qNZrd3WLLHvYXmLKVdig1GHpMSdRU8gtr39QGezv8BZdhwBjN2K8bIYHmCiZu6YmvtDYauvhUl5NLZGeXIE98xe+oTgOqDFLXCfWcNtCzxjp7aL0JQI43F+so0T5GJdPbZMRFHnExz00KFNAf3CUCzZmF02mePGkyJI122NzUazOebB0dypyUmy9q719/LD/gYJQg/xAAaiIm9gHy7UIH/P5QpUjuuazwbTjf6PgOBqBG0v7M/P6m5WlH"
    let ed25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPedzgYpkenlItq1qPlNxxDzmNtS7zDmBy3KUT2YqGPL"

    var repository: KnownHostRepository!

    override func setUpWithError() throws {
        repository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
    }

    private func store(_ openSSHKey: String, keyType: String, host: String = "server.example.com", port: Int = 22) throws {
        try repository.save(KnownHost(hostname: host, port: port, keyType: keyType,
                                      keyFingerprint: "SHA256:test", openSSHPublicKey: openSSHKey))
    }

    func testUnknownHostUsesTrustOnFirstUse() throws {
        let (_, capturer) = try HostKeyTrust.validator(for: "new.example.com", port: 22, repository: repository)
        XCTAssertNotNil(capturer)
    }

    func testStoredEd25519KeyIsEnforced() throws {
        try store(ed25519Key, keyType: "ssh-ed25519")
        let (_, capturer) = try HostKeyTrust.validator(for: "server.example.com", port: 22, repository: repository)
        XCTAssertNil(capturer, "A stored key must be enforced, not re-trusted on first use")
    }

    func testStoredRSAKeyIsEnforcedBeforeAnyConnection() throws {
        // Previously ssh-rsa only parsed after Citadel registered it during connect, so the
        // first connection after launch fell through to trust-on-first-use.
        try store(rsaKey, keyType: "ssh-rsa")
        let (_, capturer) = try HostKeyTrust.validator(for: "server.example.com", port: 22, repository: repository)
        XCTAssertNil(capturer)
    }

    func testRecordIsScopedToPort() throws {
        try store(ed25519Key, keyType: "ssh-ed25519", port: 22)
        let (_, capturer) = try HostKeyTrust.validator(for: "server.example.com", port: 2222, repository: repository)
        XCTAssertNotNil(capturer)
    }

    func testUnreadableStoredKeyFailsClosed() throws {
        try store("ssh-ed25519 not-base64!", keyType: "ssh-ed25519")
        XCTAssertThrowsError(try HostKeyTrust.validator(for: "server.example.com", port: 22, repository: repository)) { error in
            guard case HostKeyTrustError.unreadableStoredKey = error else {
                return XCTFail("Expected unreadableStoredKey, got \(error)")
            }
        }
    }

    func testMissingRepositoryFailsClosed() {
        XCTAssertThrowsError(try HostKeyTrust.validator(for: "server.example.com", port: 22, repository: nil))
    }
}
