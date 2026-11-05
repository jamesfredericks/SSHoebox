import XCTest
@testable import SSHoeboxCore

final class AuthorizedKeysTests: XCTestCase {
    func testPublicKeyLinesMatchSSHKeygen() throws {
        let cases = [(TestKeys.rsaPKCS1, TestKeys.rsaPKCS1Public), (TestKeys.rsaPKCS8, TestKeys.rsaPKCS8Public),
                     (TestKeys.rsa, TestKeys.rsaPublic)]
        for (pem, expected) in cases {
            let line = try AuthorizedKeys.publicKeyLine(fromPEM: pem, comment: "me@mac")
            let fields = expected.split(separator: " ")
            XCTAssertTrue(line.hasPrefix("\(fields[0]) \(fields[1])"), line)
            XCTAssertTrue(line.hasSuffix(" me@mac"))
        }
        XCTAssertTrue(try AuthorizedKeys.publicKeyLine(fromPEM: TestKeys.ed25519).hasPrefix("ssh-ed25519 "))
        XCTAssertTrue(try AuthorizedKeys.publicKeyLine(fromPEM: TestKeys.ecPKCS8).hasPrefix("ecdsa-sha2-nistp256 "))
    }

    func testEncryptedOpenSSHKeysNeedNoPassphrase() throws {
        let line = try AuthorizedKeys.publicKeyLine(fromPEM: TestKeys.rsaEncrypted)
        let expected = TestKeys.rsaEncryptedPublic.split(separator: " ")
        XCTAssertEqual(line, "\(expected[0]) \(expected[1])")
        XCTAssertThrowsError(try AuthorizedKeys.publicKeyLine(fromPEM: TestKeys.rsaPKCS1LegacyEncrypted))
    }

    func testCommentsAreSanitized() {
        XCTAssertEqual(AuthorizedKeys.sanitizedComment("a'b\"c$(d)`e`\\f\ng"), "abcdefg")
    }

    func testRefusesSomethingThatIsntAPublicKeyLine() {
        XCTAssertThrowsError(try AuthorizedKeys.installCommand(for: "ssh-ed25519 abc'; rm -rf ~"))
        XCTAssertThrowsError(try AuthorizedKeys.installCommand(for: "justoneword"))
    }

    /// Runs the real command under sh with HOME pointed at a temporary folder.
    func testInstallCommandAddsOnceAndKeepsExistingLines() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let line = try AuthorizedKeys.publicKeyLine(fromPEM: TestKeys.ed25519, comment: "laptop")
        let command = try AuthorizedKeys.installCommand(for: line)

        func run() throws -> String {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", command]
            process.environment = ["HOME": home.path, "PATH": "/usr/bin:/bin"]
            let pipe = Pipe()
            process.standardOutput = pipe
            try process.run()
            process.waitUntilExit()
            return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        }

        XCTAssertEqual(AuthorizedKeys.parse(output: try run()), .added)
        let file = home.appendingPathComponent(".ssh/authorized_keys")
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), line + "\n")
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
        let dirMode = try FileManager.default.attributesOfItem(atPath: file.deletingLastPathComponent().path)[.posixPermissions] as? Int
        XCTAssertEqual(dirMode, 0o700)

        XCTAssertEqual(AuthorizedKeys.parse(output: try run()), .alreadyPresent)

        // An existing file without a trailing newline keeps its last line intact.
        try "ssh-rsa AAAAexisting old".write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(AuthorizedKeys.parse(output: try run()), .added)
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "ssh-rsa AAAAexisting old\n" + line + "\n")
    }
}
