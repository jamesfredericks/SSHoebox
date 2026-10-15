import XCTest
@testable import SSHoeboxCore

final class SSHConfigParserTests: XCTestCase {

    private func parse(_ config: String) -> [SSHConfigParser.ConfigHost] {
        SSHConfigParser.parse(string: config)
    }

    private func host(_ alias: String, in hosts: [SSHConfigParser.ConfigHost],
                      file: StaticString = #filePath, line: UInt = #line) -> SSHConfigParser.ConfigHost? {
        let match = hosts.first { $0.alias == alias }
        XCTAssertNotNil(match, "no entry for \(alias)", file: file, line: line)
        return match
    }

    func testBasicHost() throws {
        let hosts = parse("""
        Host web
            HostName web.example.com
            Port 2222
            User deploy
            IdentityFile ~/.ssh/id_ed25519
        """)
        XCTAssertEqual(hosts.count, 1)
        let web = try XCTUnwrap(hosts.first)
        XCTAssertEqual(web.alias, "web")
        XCTAssertEqual(web.hostname, "web.example.com")
        XCTAssertEqual(web.port, 2222)
        XCTAssertEqual(web.user, "deploy")
        XCTAssertEqual(web.identityFile, (("~/.ssh/id_ed25519") as NSString).expandingTildeInPath)
    }

    func testDefaultsWhenOptionsMissing() throws {
        let web = try XCTUnwrap(parse("Host web").first)
        XCTAssertEqual(web.hostname, "web")
        XCTAssertEqual(web.port, 22)
        XCTAssertEqual(web.user, "")
        XCTAssertNil(web.identityFile)
    }

    func testEqualsSyntax() throws {
        let hosts = parse("""
        Host=a
          HostName=a.example.com
          Port = 2200
          User =alice
        Host = b
          HostName= b.example.com
        """)
        XCTAssertEqual(hosts.map(\.alias), ["a", "b"])
        let a = try XCTUnwrap(host("a", in: hosts))
        XCTAssertEqual(a.hostname, "a.example.com")
        XCTAssertEqual(a.port, 2200)
        XCTAssertEqual(a.user, "alice")
        XCTAssertEqual(host("b", in: hosts)?.hostname, "b.example.com")
    }

    func testCaseInsensitiveKeywordsTabsAndComments() throws {
        let hosts = parse("""
        # leading comment
        HOST\tweb   # trailing comment
        \thostname\tweb.example.com
          # indented comment
        \tPORT\t2022

        \tuSeR root
        """)
        XCTAssertEqual(hosts.count, 1)
        let web = try XCTUnwrap(hosts.first)
        XCTAssertEqual(web.alias, "web")
        XCTAssertEqual(web.hostname, "web.example.com")
        XCTAssertEqual(web.port, 2022)
        XCTAssertEqual(web.user, "root")
    }

    func testMultiplePatternsProduceAnEntryEach() {
        let hosts = parse("""
        Host a b c
            User shared
            HostName %h.internal
        """)
        XCTAssertEqual(hosts.map(\.alias), ["a", "b", "c"])
        XCTAssertEqual(hosts.map(\.user), ["shared", "shared", "shared"])
        XCTAssertEqual(hosts.map(\.hostname), ["a.internal", "b.internal", "c.internal"])
    }

    func testWildcardAndNegatedPatternsAreNotImported() {
        let hosts = parse("""
        Host *
            ServerAliveInterval 30
        Host *.example.com !bastion.example.com prod-?
            User ops
        Host real
        """)
        XCTAssertEqual(hosts.map(\.alias), ["real"])
    }

    func testFirstObtainedValueWins() throws {
        let hosts = parse("""
        Host web
            HostName first.example.com
            HostName second.example.com
            User alice
            Port 2201
        Host web
            User bob
            Port 2202
        """)
        XCTAssertEqual(hosts.count, 1, "duplicate Host blocks merge into one entry")
        let web = try XCTUnwrap(hosts.first)
        XCTAssertEqual(web.hostname, "first.example.com")
        XCTAssertEqual(web.user, "alice")
        XCTAssertEqual(web.port, 2201)
    }

    func testWildcardBlocksApplyInFileOrder() throws {
        let hosts = parse("""
        User globaluser

        Host web
            Port 2200
        Host db
            User dbadmin
        Host *
            User fallback
            Port 2299
        """)
        let web = try XCTUnwrap(host("web", in: hosts))
        // Global section (before any Host) comes first, so it beats `Host *`
        XCTAssertEqual(web.user, "globaluser")
        XCTAssertEqual(web.port, 2200)
        let db = try XCTUnwrap(host("db", in: hosts))
        XCTAssertEqual(db.user, "globaluser")
        XCTAssertEqual(db.port, 2299)
    }

    func testWildcardBeforeHostWins() throws {
        let hosts = parse("""
        Host *.corp
            User corpuser
        Host app.corp
            User appuser
        """)
        XCTAssertEqual(host("app.corp", in: hosts)?.user, "corpuser")
    }

    func testNegatedPatternExcludesHost() throws {
        let hosts = parse("""
        Host * !bastion
            User everyone
        Host bastion web
        """)
        XCTAssertEqual(host("bastion", in: hosts)?.user, "")
        XCTAssertEqual(host("web", in: hosts)?.user, "everyone")
    }

    func testHostPatternMatchingIsCaseInsensitive() throws {
        let hosts = parse("""
        Host WEB
            Port 2200
        Host web
            User late
        Host W?b
            User glob
        """)
        XCTAssertEqual(hosts.map(\.alias), ["WEB"])
        XCTAssertEqual(hosts.first?.port, 2200)
        XCTAssertEqual(hosts.first?.user, "late")
    }

    func testMatchBlockOptionsDoNotLeakIntoPreviousHost() throws {
        let hosts = parse("""
        Host web
            HostName web.example.com
        Match host web.example.com exec "true"
            User matched
            Port 9999
        Host db
            User dbuser
        """)
        let web = try XCTUnwrap(host("web", in: hosts))
        XCTAssertEqual(web.user, "")
        XCTAssertEqual(web.port, 22)
        XCTAssertEqual(host("db", in: hosts)?.user, "dbuser")
    }

    func testMatchAllAppliesToEveryHost() throws {
        let hosts = parse("""
        Host web
            Port 2200
        Match all
            User everyone
        """)
        let web = try XCTUnwrap(hosts.first)
        XCTAssertEqual(web.port, 2200)
        XCTAssertEqual(web.user, "everyone")
    }

    func testQuotedValues() throws {
        let hosts = parse("""
        Host "my server" plain
            IdentityFile "/Users/me/My Keys/id_ed25519"
            User 'svc account'
            HostName "with\\"quote.example.com"
        """)
        XCTAssertEqual(hosts.map(\.alias), ["my server", "plain"])
        let mine = try XCTUnwrap(hosts.first)
        XCTAssertEqual(mine.identityFile, "/Users/me/My Keys/id_ed25519")
        XCTAssertEqual(mine.user, "svc account")
        XCTAssertEqual(mine.hostname, "with\"quote.example.com")
    }

    func testHashInsideQuotesIsNotAComment() throws {
        let hosts = parse("""
        Host web
            User "a#b"
        """)
        XCTAssertEqual(hosts.first?.user, "a#b")
    }

    func testInvalidPortFallsThroughToLaterValue() throws {
        let hosts = parse("""
        Host web
            Port notaport
        Host *
            Port 70000
            Port 2222
        """)
        XCTAssertEqual(hosts.first?.port, 2222)
    }

    func testHostnameTokenExpansion() throws {
        let hosts = parse("""
        Host web
            HostName %h.example.com%%
        """)
        XCTAssertEqual(hosts.first?.hostname, "web.example.com%")
    }

    func testCRLFLineEndings() throws {
        let hosts = parse("Host web\r\n  HostName web.example.com\r\n  User root\r\n")
        XCTAssertEqual(hosts.count, 1)
        XCTAssertEqual(hosts.first?.hostname, "web.example.com")
        XCTAssertEqual(hosts.first?.user, "root")
    }

    func testIncludeIgnoredWithoutBaseDirectory() {
        let hosts = parse("""
        Include config.d/*
        Host web
        """)
        XCTAssertEqual(hosts.map(\.alias), ["web"])
    }

    func testIncludeFromFile() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHConfigParserTests-\(UUID().uuidString)")
        let confD = dir.appendingPathComponent("config.d")
        try FileManager.default.createDirectory(at: confD, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        try """
        Host included-b
            HostName b.example.com
        """.write(to: confD.appendingPathComponent("20-b"), atomically: true, encoding: .utf8)
        try """
        Host included-a
            HostName a.example.com
        Host main
            User from-include
        """.write(to: confD.appendingPathComponent("10-a"), atomically: true, encoding: .utf8)
        // Includes itself: must stop at the depth limit rather than recurse forever
        try "Include loop\nHost looped\n".write(to: dir.appendingPathComponent("loop"), atomically: true, encoding: .utf8)
        try """
        Include config.d/* "does not exist"
        Include loop
        Host main
            User from-main
        """.write(to: dir.appendingPathComponent("config"), atomically: true, encoding: .utf8)

        let hosts = try SSHConfigParser.parse(contentsOf: dir.appendingPathComponent("config"))
        XCTAssertEqual(hosts.map(\.alias), ["included-a", "main", "included-b", "looped"])
        XCTAssertEqual(host("included-a", in: hosts)?.hostname, "a.example.com")
        XCTAssertEqual(host("included-b", in: hosts)?.hostname, "b.example.com")
        // The include comes first in the file, so its value is obtained first
        XCTAssertEqual(host("main", in: hosts)?.user, "from-include")
    }

    func testGlobMatch() {
        XCTAssertTrue(SSHConfigParser.globMatch("*", ""))
        XCTAssertTrue(SSHConfigParser.globMatch("*.example.com", "a.b.example.com"))
        XCTAssertTrue(SSHConfigParser.globMatch("web-??", "web-01"))
        XCTAssertFalse(SSHConfigParser.globMatch("web-??", "web-1"))
        XCTAssertFalse(SSHConfigParser.globMatch("*.example.com", "example.com"))
        XCTAssertTrue(SSHConfigParser.globMatch("a*b*c", "aXXbYYc"))
        XCTAssertFalse(SSHConfigParser.globMatch("a*b*c", "aXXbYY"))
    }
}
