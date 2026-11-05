import XCTest
@testable import SSHoeboxCore

/// Logs in to a real OpenSSH server with stored keys. Skipped unless `SSHOEBOX_LIVE_SSHD_DIR`
/// names a folder holding a running test server's keys:
///
///     ssh-keygen -t ed25519 -N '' -f host_ed25519
///     ssh-keygen -t rsa -m PEM   -N ''   -f rsa_pkcs1        # BEGIN RSA PRIVATE KEY
///     ssh-keygen -t rsa -m PKCS8 -N ''   -f rsa_pkcs8        # BEGIN PRIVATE KEY
///     ssh-keygen -t rsa          -N 'pw' -f rsa_openssh_enc  # BEGIN OPENSSH PRIVATE KEY
///     ssh-keygen -t rsa          -N ''   -f rsa_unauthorized
///     cat rsa_pkcs1.pub rsa_pkcs8.pub rsa_openssh_enc.pub > authorized_keys
///
/// and an `sshd_config` with `Port 2299`, `ListenAddress 127.0.0.1`, `HostKey`,
/// `AuthorizedKeysFile` and `PidFile` in that folder, `PasswordAuthentication no`,
/// `KbdInteractiveAuthentication no`, `UsePAM no`, `StrictModes no`; run it as yourself with
/// `/usr/sbin/sshd -D -e -f <folder>/sshd_config`.
@MainActor
final class LiveSSHDTests: XCTestCase {
    private var folder: URL!

    override func setUpWithError() throws {
        guard let path = ProcessInfo.processInfo.environment["SSHOEBOX_LIVE_SSHD_DIR"] else {
            throw XCTSkip("set SSHOEBOX_LIVE_SSHD_DIR to run against a real sshd")
        }
        folder = URL(fileURLWithPath: path)
    }

    private func login(key file: String, passphrase: String? = nil) async throws -> String {
        let pem = try String(contentsOf: folder.appendingPathComponent(file), encoding: .utf8)
        let manager = SSHSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
        await manager.connect(host: "127.0.0.1", port: 2299, username: NSUserName(), pemKey: pem, passphrase: passphrase)
        let attempt = try XCTUnwrap(manager.lastLoginAttemptID)
        var text = ""
        for _ in 0..<500 {
            text = LoginLogBuffer.shared.entries.filter { $0.attemptID == attempt }.map(\.line).joined(separator: "\n")
            if text.contains("] failed: ") || text.contains("login complete") { break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        manager.disconnect()
        return text
    }

    func testRSAKeysInEveryFormatLogIn() async throws {
        for (file, passphrase) in [("rsa_pkcs1", nil), ("rsa_pkcs8", nil), ("rsa_openssh_enc", "pw")] {
            let text = try await login(key: file, passphrase: passphrase)
            XCTAssertTrue(text.contains("auth: SUCCESS"), "\(file):\n\(text)")
            XCTAssertTrue(text.contains("method publickey rsa-sha2-512 (ssh-rsa key) with signature"), "\(file):\n\(text)")
            XCTAssertFalse(text.contains("offering the key as rsa-sha2-256"), "\(file): the first algorithm should be accepted:\n\(text)")
        }
    }

    /// Needs `Subsystem sftp /usr/libexec/sftp-server` in the test server's config.
    func testSFTPLogsInWithAnRSAKey() async throws {
        let pem = try String(contentsOf: folder.appendingPathComponent("rsa_pkcs1"), encoding: .utf8)
        let manager = SFTPSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
        await manager.connect(host: "127.0.0.1", port: 2299, username: NSUserName(), pemKey: pem)
        for _ in 0..<500 where manager.connectionState != .connected {
            if case .failed = manager.connectionState { break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertEqual(manager.connectionState, .connected, manager.errorMessage ?? "")
        manager.disconnect()
    }

    func testUnauthorizedRSAKeyIsRejectedClearly() async throws {
        let text = try await login(key: "rsa_unauthorized")
        XCTAssertTrue(text.contains("rejected the key as rsa-sha2-512 and rsa-sha2-256"), text)
        XCTAssertTrue(text.contains("failed: SSHLoginError: The server rejected the key."), text)
    }
}
