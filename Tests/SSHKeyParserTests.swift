import XCTest
@testable import SSHoeboxCore

final class SSHKeyParserTests: XCTestCase {
    private func crlf(_ pem: String) -> String {
        pem.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n"
    }

    func testEncryptedKeyDetected() {
        XCTAssertTrue(SSHKeyParser.isEncryptedKey(TestKeys.ed25519Encrypted))
        XCTAssertFalse(SSHKeyParser.isEncryptedKey(TestKeys.ed25519))
    }

    func testEncryptedKeyWithCRLFDetected() {
        XCTAssertTrue(SSHKeyParser.isEncryptedKey(crlf(TestKeys.ed25519Encrypted)))
        XCTAssertTrue(SSHKeyParser.isEncryptedKey(crlf(TestKeys.rsaEncrypted)))
        XCTAssertFalse(SSHKeyParser.isEncryptedKey(crlf(TestKeys.ed25519)))
    }

    func testKeyWithCRLFParses() throws {
        let lf = try SSHKeyParser.publicKeyBlob(fromPEM: TestKeys.ed25519)
        let windows = try SSHKeyParser.publicKeyBlob(fromPEM: crlf(TestKeys.ed25519))
        XCTAssertEqual(lf, windows)
        XCTAssertNoThrow(try SSHKeyParser.publicKeyBlob(fromPEM: crlf(TestKeys.ed25519Encrypted),
                                                        passphrase: TestKeys.passphrase))
    }

    func testNormalizedPEMTrimsStrayWhitespace() {
        let messy = "  " + TestKeys.ed25519.replacingOccurrences(of: "\n", with: " \r\n\r\n") + "\r\n  "
        XCTAssertEqual(SSHKeyParser.normalizedPEM(messy), TestKeys.ed25519 + "\n")
    }
}
