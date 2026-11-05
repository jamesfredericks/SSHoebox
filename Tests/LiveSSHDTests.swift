import XCTest
import Foundation
@testable import SSHoeboxCore

/// Logs in to a real OpenSSH server with stored keys. Skipped unless `SSHOEBOX_LIVE_SSHD_DIR`
/// names a folder holding a running test server's keys:
///
///     ssh-keygen -t ed25519 -N '' -f host_ed25519
///     ssh-keygen -t rsa -m PEM   -N ''   -f rsa_pkcs1        # BEGIN RSA PRIVATE KEY
///     ssh-keygen -t rsa -m PKCS8 -N ''   -f rsa_pkcs8        # BEGIN PRIVATE KEY
///     ssh-keygen -t rsa          -N 'pw' -f rsa_openssh_enc  # BEGIN OPENSSH PRIVATE KEY
///     ssh-keygen -t rsa          -N ''   -f rsa_unauthorized
///     ssh-keygen -t ecdsa -b 256          -N ''   -f ecdsa_openssh
///     ssh-keygen -t ecdsa -b 384          -N 'pw' -f ecdsa_openssh_enc
///     ssh-keygen -t ecdsa -b 521 -m PEM   -N ''   -f ecdsa_sec1   # BEGIN EC PRIVATE KEY
///     ssh-keygen -t ecdsa -b 256 -m PKCS8 -N ''   -f ecdsa_pkcs8  # BEGIN PRIVATE KEY
///     cat rsa_pkcs1.pub rsa_pkcs8.pub rsa_openssh_enc.pub ecdsa_*.pub > authorized_keys
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

    private func keyLogin(_ file: String, passphrase: String? = nil) throws -> SSHLogin {
        let pem = try String(contentsOf: folder.appendingPathComponent(file), encoding: .utf8)
        return SSHLogin(host: "127.0.0.1", port: 2299, username: NSUserName(),
                        auth: .privateKey(pem: pem, passphrase: passphrase))
    }

    private func logText(_ manager: SSHSessionManager) throws -> String {
        let attempt = try XCTUnwrap(manager.lastLoginAttemptID)
        return LoginLogBuffer.shared.entries.filter { $0.attemptID == attempt }.map(\.line).joined(separator: "\n")
    }

    /// Connects and waits until the login completes or fails; returns the manager, still
    /// connected if it worked, and its login log.
    private func session(_ target: SSHLogin, via jumps: [SSHLogin] = [],
                         options: SSHSessionOptions = SSHSessionOptions(keepAliveInterval: 0),
                         output: ((Data) -> Void)? = nil) async throws -> (SSHSessionManager, String) {
        let manager = SSHSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
        manager.onOutput = output
        await manager.connect(target, via: jumps, options: options)
        var text = ""
        for _ in 0..<500 {
            text = try logText(manager)
            if text.contains("] failed: ") || text.contains("login complete") { break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        return (manager, text)
    }

    private func login(key file: String, passphrase: String? = nil) async throws -> String {
        let (manager, text) = try await session(try keyLogin(file, passphrase: passphrase))
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

    func testECDSAKeysInEveryFormatLogIn() async throws {
        let cases: [(String, String?, String)] = [
            ("ecdsa_openssh", nil, "ecdsa-sha2-nistp256 OpenSSH"),
            ("ecdsa_openssh_enc", "pw", "ecdsa-sha2-nistp384 OpenSSH"),
            ("ecdsa_sec1", nil, "ecdsa-sha2-nistp521 SEC1"),
            ("ecdsa_pkcs8", nil, "ecdsa-sha2-nistp256 PKCS#8"),
        ]
        for (file, passphrase, summary) in cases {
            let text = try await login(key: file, passphrase: passphrase)
            XCTAssertTrue(text.contains("auth: SUCCESS"), "\(file):\n\(text)")
            XCTAssertTrue(text.contains("key: \(summary) key SHA256:"), "\(file):\n\(text)")
        }
    }

    /// ssh -J: the "jump host" is the same server, which then connects to itself.
    func testJumpHostRoute() async throws {
        let jump = try keyLogin("ecdsa_openssh")
        let target = try keyLogin("rsa_pkcs1")
        var output = Data()
        let options = SSHSessionOptions(keepAliveInterval: 0, startupCommand: "echo STARTUP_$((40+2))")
        let (manager, text) = try await session(target, via: [jump], options: options) { output.append($0) }
        defer { manager.disconnect() }
        XCTAssertTrue(text.contains("route: logged in to jump host 1"), text)
        XCTAssertTrue(text.contains("route: tunnelling to target"), text)
        XCTAssertTrue(text.contains("auth: SUCCESS"), text)
        XCTAssertEqual(manager.connectionState, .connected)

        for _ in 0..<250 where !String(decoding: output, as: UTF8.self).contains("STARTUP_42") {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertTrue(String(decoding: output, as: UTF8.self).contains("STARTUP_42"), "startup command ran")
        let ran = try await manager.run("echo exec-$((6*7))")
        XCTAssertEqual(ran.trimmingCharacters(in: .whitespacesAndNewlines), "exec-42")
    }

    func testFailingJumpHostIsNamed() async throws {
        let jump = try keyLogin("rsa_unauthorized")
        let (manager, text) = try await session(try keyLogin("rsa_pkcs1"), via: [jump])
        defer { manager.disconnect() }
        guard case .failed(let message) = manager.connectionState else { return XCTFail("should fail:\n\(text)") }
        XCTAssertTrue(message.hasPrefix("Jump host 1 (\(jump.endpoint)):"), message)
    }

    /// A local forward to the server's own SSH port: the banner comes back through the tunnel.
    func testPortForwardCarriesTraffic() async throws {
        let forward = PortForward(localPort: 22990, remoteHost: "127.0.0.1", remotePort: 2299)
        let options = SSHSessionOptions(keepAliveInterval: 0, portForwards: [forward])
        let (manager, text) = try await session(try keyLogin("rsa_pkcs1"), options: options)
        defer { manager.disconnect() }
        XCTAssertTrue(text.contains("login complete"), text)
        for _ in 0..<100 where manager.forwards.first?.state != .listening {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertEqual(manager.forwards.first?.state, .listening)

        let banner = try await Self.readBanner(port: 22990)
        XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), banner)

        // A second session can't bind the same port, and says why.
        let (second, _) = try await session(try keyLogin("rsa_pkcs1"), options: options)
        defer { second.disconnect() }
        for _ in 0..<100 where second.forwards.first?.state == .stopped {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        guard case .failed(let reason) = second.forwards.first?.state else { return XCTFail("second bind should fail") }
        XCTAssertTrue(reason.contains("already in use"), reason)

        manager.stopForward(id: forward.id)
        XCTAssertEqual(manager.forwards.first?.state, .stopped)
    }

    func testKeepAlivesAreAnswered() async throws {
        let repository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
        let trace = LoginTrace(sink: { _, _ in })
        let preparer = SSHLoginPreparer(repository: repository, trace: trace, prompter: nil)
        guard case .ready(let step) = await preparer.prepare(try keyLogin("ecdsa_openssh")) else { return XCTFail() }
        let route = try await SSHRoute.connect([step], repository: repository, trace: trace)
        for _ in 0..<3 { try await route.client.sendKeepAlive() }
        await route.close()
        XCTAssertFalse(route.isConnected)
    }

    func testSFTPThroughAJumpHost() async throws {
        let manager = SFTPSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
        await manager.connect(try keyLogin("rsa_pkcs8"), via: [try keyLogin("ecdsa_sec1")],
                              options: SSHSessionOptions(keepAliveInterval: 0))
        XCTAssertEqual(manager.connectionState, .connected, manager.errorMessage ?? "")
        manager.disconnect()
    }

    private static func readBanner(port: Int) async throws -> String {
        try await Task.detached {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            defer { close(fd) }
            var address = sockaddr_in()
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = in_port_t(UInt16(port).bigEndian)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let connected = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard connected == 0 else { return "connect failed: \(errno)" }
            var buffer = [UInt8](repeating: 0, count: 256)
            let count = Darwin.read(fd, &buffer, buffer.count)
            return count > 0 ? String(decoding: buffer[..<count], as: UTF8.self) : "read failed"
        }.value
    }

    func testOneShotCommandThroughAJumpHost() async throws {
        let repository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
        let output = try await SSHCommandRunner.run("echo one-shot-$((2*21))", target: try keyLogin("ecdsa_pkcs8"),
                                                    via: [try keyLogin("rsa_pkcs1")], repository: repository,
                                                    purpose: "test")
        XCTAssertEqual(output.trimmingCharacters(in: .whitespacesAndNewlines), "one-shot-42")
        do {
            _ = try await SSHCommandRunner.run("true", target: try keyLogin("rsa_openssh_enc"), repository: repository,
                                               purpose: "test")
            XCTFail("an encrypted key without its passphrase can't log in here")
        } catch SSHCommandRunner.RunError.needsPassphrase {}
    }

    func testUnauthorizedRSAKeyIsRejectedClearly() async throws {
        let text = try await login(key: "rsa_unauthorized")
        XCTAssertTrue(text.contains("rejected the key as rsa-sha2-512 and rsa-sha2-256"), text)
        XCTAssertTrue(text.contains("failed: SSHLoginError: The server rejected the key."), text)
    }
}
