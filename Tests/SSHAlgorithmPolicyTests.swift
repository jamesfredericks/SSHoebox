import XCTest
import Citadel
import NIOSSH
@testable import SSHoeboxCore

final class SSHAlgorithmPolicyTests: XCTestCase {
    private var keyExchangeNames: [String] {
        guard case .add(let types) = SSHAlgorithmPolicy.algorithms.keyExchangeAlgorithms else {
            XCTFail("Expected key exchange algorithms to be added to NIOSSH's defaults")
            return []
        }
        return types.flatMap { $0.keyExchangeAlgorithmNames.map(String.init) }
    }

    private var transportSchemes: [NIOSSHTransportProtection.Type] {
        guard case .add(let types) = SSHAlgorithmPolicy.algorithms.transportProtectionSchemes else {
            XCTFail("Expected transport schemes to be added to NIOSSH's defaults")
            return []
        }
        return types
    }

    func testNoSHA1KeyExchange() {
        XCTAssertFalse(keyExchangeNames.contains { $0.hasSuffix("-sha1") }, "\(keyExchangeNames)")
        XCTAssertTrue(keyExchangeNames.contains("diffie-hellman-group14-sha256"))
    }

    func testNoSHA1MACs() {
        let macs = transportSchemes.flatMap { $0.macNames }
        XCTAssertFalse(macs.contains("hmac-sha1"), "\(macs)")
        XCTAssertTrue(macs.contains("hmac-sha2-256"))
    }

    func testKeepsAESCTRFallback() {
        XCTAssertTrue(transportSchemes.contains { $0.cipherName == "aes128-ctr" })
    }
}
