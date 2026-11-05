import XCTest
import CryptoKit
import SSHoeboxCore
@testable import SSHoeboxApp

@MainActor
final class AppNavigatorTests: XCTestCase {
    private let key = SymmetricKey(size: .bits256)

    func testParsesSSHLinks() {
        XCTAssertEqual(SSHLink(url: URL(string: "ssh://admin@10.0.0.5:2222")!),
                       SSHLink(user: "admin", host: "10.0.0.5", port: 2222))
        XCTAssertEqual(SSHLink(url: URL(string: "ssh://web.example")!), SSHLink(user: nil, host: "web.example", port: nil))
        XCTAssertEqual(SSHLink(url: URL(string: "ssh://root;fingerprint=SHA256-abc@h")!)?.user, "root")
        XCTAssertEqual(SSHLink(url: URL(string: "ssh://[fe80::1]:22")!)?.host, "fe80::1")
        XCTAssertNil(SSHLink(url: URL(string: "https://example.com")!))
        XCTAssertNil(SSHLink(url: URL(string: "ssh:")!))
    }

    func testLinkMatchesTheSavedHostWithTheSameAddressPortAndUser() throws {
        func host(_ name: String, _ address: String, port: Int = 22, user: String, last: TimeInterval? = nil) throws -> SavedHost {
            try SavedHost.encrypted(name: name, hostname: address, port: port, protocolType: "ssh", user: user,
                                    groupId: nil, lastConnectedAt: last.map(Date.init(timeIntervalSince1970:)), using: key)
        }
        let hosts = [
            try host("a", "web.example", user: "deploy", last: 10),
            try host("b", "WEB.example", user: "deploy", last: 20),
            try host("c", "web.example", port: 2222, user: "deploy"),
            try host("d", "web.example", user: "root"),
        ]
        let name = { (h: SavedHost?) in h?.decryptedName(using: self.key) }
        XCTAssertEqual(name(SSHLink(user: "deploy", host: "web.example", port: nil).bestMatch(in: hosts, vaultKey: key)), "b",
                       "the most recently used match wins")
        XCTAssertEqual(name(SSHLink(user: nil, host: "web.example", port: 2222).bestMatch(in: hosts, vaultKey: key)), "c")
        XCTAssertEqual(name(SSHLink(user: "root", host: "web.example", port: 22).bestMatch(in: hosts, vaultKey: key)), "d")
        XCTAssertNil(SSHLink(user: "nobody", host: "web.example", port: nil).bestMatch(in: hosts, vaultKey: key))
    }

    func testOpenSetsTheRouteAndAOneShotAction() {
        let navigator = AppNavigator()
        navigator.sidebar = .preferences
        navigator.open(hostId: "h1", action: .files)
        XCTAssertEqual(navigator.sidebar, .hosts)
        XCTAssertEqual(navigator.hostPath, [AppNavigator.HostRoute(hostId: "h1")])
        XCTAssertNil(navigator.takeAction(for: "other"))
        XCTAssertEqual(navigator.takeAction(for: "h1"), .files)
        XCTAssertNil(navigator.takeAction(for: "h1"), "performed once")
    }
}
