import XCTest
import CryptoKit
@testable import SSHoeboxCore

final class HostOptionsTests: XCTestCase {
    private let key = SymmetricKey(size: .bits256)

    // MARK: - Port forward specs

    func testParsesLocalForwardSpecs() {
        let config = PortForward.parse("8080 db.internal:5432")
        XCTAssertEqual(config?.localPort, 8080)
        XCTAssertEqual(config?.remoteHost, "db.internal")
        XCTAssertEqual(config?.remotePort, 5432)
        XCTAssertEqual(config?.bindAddress, "127.0.0.1")

        let commandLine = PortForward.parse("127.0.0.1:9000:10.0.0.5:443")
        XCTAssertEqual(commandLine?.localPort, 9000)
        XCTAssertEqual(commandLine?.remoteHost, "10.0.0.5")

        let ipv6 = PortForward.parse("[::1]:8443 [fe80::1]:443")
        XCTAssertEqual(ipv6?.bindAddress, "::1")
        XCTAssertEqual(ipv6?.remoteHost, "fe80::1")
        XCTAssertEqual(ipv6?.remotePort, 443)

        XCTAssertEqual(PortForward.parse("*:8080 web:80")?.bindAddress, "0.0.0.0")
        XCTAssertEqual(PortForward.parse("localhost:8080 web:80")?.bindAddress, "127.0.0.1")
        XCTAssertNil(PortForward.parse("/tmp/sock web:80"), "unix sockets aren't supported")
        XCTAssertNil(PortForward.parse("70000 web:80"))
        XCTAssertNil(PortForward.parse("8080"))
        XCTAssertEqual(PortForward.parse("8080 db:5432")?.summary, "8080 → db:5432")
    }

    func testTagListParsing() {
        XCTAssertEqual(HostOptions.tags(fromList: " prod, web ,, Prod , db"), ["prod", "web", "db"])
    }

    // MARK: - Stored options

    func testOptionsRoundTripEncrypted() throws {
        var host = SavedHost(name: "n", hostname: "h")
        XCTAssertEqual(host.decryptedOptions(using: key), HostOptions(), "no options stored yet")
        let options = HostOptions(jumpHostId: "bastion", keepAliveInterval: 15,
                                  portForwards: [PortForward(localPort: 1, remoteHost: "x", remotePort: 2)],
                                  startupCommand: "sudo -i", tags: ["prod"], isFavorite: true)
        try host.setOptions(options, using: key)
        let blob = try XCTUnwrap(host.encryptedOptions)
        XCTAssertFalse(String(decoding: blob, as: UTF8.self).contains("bastion"), "stored encrypted")
        XCTAssertEqual(host.decryptedOptions(using: key), options)

        // Bound to the row: another host's id can't read it.
        var other = host
        other.id = "other"
        XCTAssertEqual(other.decryptedOptions(using: key), HostOptions())

        try host.setOptions(HostOptions(), using: key)
        XCTAssertNil(host.encryptedOptions, "default options store nothing")
    }

    func testOptionsFromOlderVersionsStillDecode() throws {
        let json = #"{"jumpHostId":"j","portForwards":[{"localPort":1,"remoteHost":"r","remotePort":2}]}"#
        let options = try JSONDecoder().decode(HostOptions.self, from: Data(json.utf8))
        XCTAssertEqual(options.jumpHostId, "j")
        XCTAssertEqual(options.portForwards.first?.autoStart, true)
        XCTAssertEqual(options.tags, [])
        XCTAssertFalse(options.isFavorite)
    }

    func testHostOptionsSurviveTheDatabase() throws {
        let db = try DatabaseManager(inMemory: true)
        var host = try SavedHost.encrypted(name: "web", hostname: "web.example", port: 22, protocolType: "ssh",
                                           user: "deploy", groupId: nil, using: key)
        try host.setOptions(HostOptions(tags: ["a"], isFavorite: true), using: key)
        try HostRepository(dbManager: db).save(host)
        let loaded = try XCTUnwrap(HostRepository(dbManager: db).get(id: host.id))
        XCTAssertEqual(loaded.decryptedOptions(using: key).tags, ["a"])
    }

    // MARK: - Connection plans

    private func makeHost(_ db: DatabaseManager, _ name: String, jump: String? = nil, keepAlive: Int? = nil,
                          password: String? = nil) throws -> SavedHost {
        var host = try SavedHost.encrypted(id: name, name: name, hostname: "\(name).example", port: 22,
                                           protocolType: "ssh", user: "u-\(name)", groupId: nil, using: key)
        try host.setOptions(HostOptions(jumpHostId: jump, keepAliveInterval: keepAlive, startupCommand: "  "), using: key)
        try HostRepository(dbManager: db).save(host)
        if let password {
            _ = try CredentialRepository(dbManager: db).createCredential(
                hostId: host.id, username: "", type: "password", secret: Data(password.utf8), vaultKey: key)
        }
        return host
    }

    func testPlanFollowsTheJumpChainOutermostFirst() throws {
        let db = try DatabaseManager(inMemory: true)
        _ = try makeHost(db, "edge", password: "pw")
        _ = try makeHost(db, "bastion", jump: "edge")
        let target = try makeHost(db, "app", jump: "bastion", keepAlive: 0)

        let plan = try HostConnectionPlanner(dbManager: db, vaultKey: key).plan(for: target)
        XCTAssertEqual(plan.jumps.map(\.host), ["edge.example", "bastion.example"])
        XCTAssertEqual(plan.target.endpoint, "u-app@app.example:22")
        XCTAssertEqual(plan.options.keepAliveInterval, 0, "the host's own setting wins")
        XCTAssertNil(plan.options.startupCommand, "a blank startup command isn't sent")
        guard case .password("pw") = plan.jumps[0].auth else { return XCTFail("edge uses its own password") }
        guard case .interactive = plan.target.auth else { return XCTFail("no credential: keyboard-interactive") }
    }

    func testPlanRefusesAJumpLoop() throws {
        let db = try DatabaseManager(inMemory: true)
        _ = try makeHost(db, "a", jump: "b")
        let b = try makeHost(db, "b", jump: "a")
        XCTAssertThrowsError(try HostConnectionPlanner(dbManager: db, vaultKey: key).plan(for: b)) { error in
            guard case HostConnectionPlanError.jumpLoop = error else { return XCTFail("\(error)") }
        }
    }

    func testMissingJumpHostConnectsDirectlyWithAWarning() throws {
        let db = try DatabaseManager(inMemory: true)
        let host = try makeHost(db, "app", jump: "gone")
        let plan = try HostConnectionPlanner(dbManager: db, vaultKey: key).plan(for: host)
        XCTAssertTrue(plan.jumps.isEmpty)
        XCTAssertEqual(plan.warnings.count, 1)
    }

    // MARK: - Snippets

    func testSnippetsForAHostComeBeforeGlobalOnes() throws {
        let db = try DatabaseManager(inMemory: true)
        let host = try makeHost(db, "app")
        let repo = SnippetRepository(dbManager: db)
        try repo.save(hostId: nil, name: "uptime", command: "uptime", vaultKey: key)
        try repo.save(hostId: host.id, name: "logs", command: "tail -f /var/log/syslog", vaultKey: key)
        let offered = try repo.snippets(forHost: host.id)
        XCTAssertEqual(offered.map { $0.decryptedName(using: key) }, ["logs", "uptime"])
        XCTAssertEqual(try repo.snippets(forHost: nil).count, 1)
        XCTAssertFalse(offered[0].command.contains("tail"), "stored encrypted")

        // Deleting the host deletes its snippets, and leaves tombstones for sync.
        try HostRepository(dbManager: db).delete(host)
        XCTAssertEqual(try repo.getAll().count, 1)
        let tombstones = try db.reader.read { try SyncTombstone.fetchAll($0) }
        XCTAssertTrue(tombstones.contains { $0.tableName == "snippet" })
    }

    func testSyncMergesSnippetsAndDropsThoseOfDeletedHosts() throws {
        let host = SavedHost(id: "h", name: "n", hostname: "x")
        let own = Snippet(id: "s1", hostId: "h", name: "a", command: "b")
        let global = Snippet(id: "s2", hostId: nil, name: "c", command: "d")
        let orphan = Snippet(id: "s3", hostId: "deleted", name: "e", command: "f")
        let older = Snippet(id: "s2", hostId: nil, name: "old", command: "old",
                            updatedAt: Date(timeIntervalSince1970: 0))
        let merged = VaultRecords.merge([
            VaultRecords(hosts: [host], snippets: [own, global, orphan]),
            VaultRecords(snippets: [older]),
        ])
        XCTAssertEqual(merged.snippets.map(\.id), ["s1", "s2"])
        XCTAssertEqual(merged.snippets.first { $0.id == "s2" }?.name, "c", "latest edit wins")
    }

    func testSyncSnapshotsWithoutSnippetsStillDecode() throws {
        let old = #"{"groups":[],"hosts":[],"credentials":[],"knownHosts":[],"passwordHistory":[],"tombstones":[]}"#
        let records = try JSONDecoder().decode(VaultRecords.self, from: Data(old.utf8))
        XCTAssertEqual(records.snippets, [])
    }
}

final class SSHConfigConnectionOptionsTests: XCTestCase {
    func testReadsProxyJumpForwardsAndKeepAlive() {
        let config = """
        Host *
            ServerAliveInterval 45
        Host app
            HostName 10.0.0.5
            ProxyJump admin@bastion:2222,inner
            LocalForward 8080 localhost:80
            LocalForward 127.0.0.1:5433 db:5432
        Host bastion
            HostName bastion.example
            ProxyJump none
        Host app
            LocalForward 9000 extra:90
        """
        let hosts = SSHConfigParser.parse(string: config)
        let app = hosts.first { $0.alias == "app" }
        XCTAssertEqual(app?.proxyJump, ["admin@bastion:2222", "inner"])
        XCTAssertEqual(app?.localForwards.map(\.summary), ["8080 → localhost:80", "5433 → db:5432", "9000 → extra:90"],
                       "LocalForward accumulates across blocks")
        XCTAssertEqual(app?.serverAliveInterval, 45)
        XCTAssertEqual(hosts.first { $0.alias == "bastion" }?.proxyJump, [])
    }

    func testJumpSpecs() {
        XCTAssertTrue(SSHConfigParser.parseJumpSpec("admin@bastion:2222") == ("admin", "bastion", 2222))
        XCTAssertTrue(SSHConfigParser.parseJumpSpec("bastion") == (nil, "bastion", nil))
        XCTAssertTrue(SSHConfigParser.parseJumpSpec("u@[fe80::1]:22") == ("u", "fe80::1", 22))
        XCTAssertTrue(SSHConfigParser.parseJumpSpec("fe80::1") == (nil, "fe80::1", nil), "bare IPv6 has no port")
    }
}
