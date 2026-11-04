import XCTest
import NIOCore
import NIOPosix
import NIOSSH
@testable import SSHoeboxCore

/// The login trace must say enough to debug a failed login while never recording a secret.
final class LoginTraceTests: XCTestCase {

    /// Collects trace lines instead of writing them to the unified log.
    final class CapturedLines: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: [(LoginTrace.Level, String)] = []

        var sink: LoginTrace.Sink {
            { [self] level, line in lock.withLock { stored.append((level, line)) } }
        }
        var all: [String] { lock.withLock { stored.map(\.1) } }
        var errors: [String] { lock.withLock { stored.filter { $0.0 == .error }.map(\.1) } }
        var text: String { all.joined(separator: "\n") }
    }

    private let password = "hunter2-SECRET-pw"
    private let typedCode = "918273"

    private var group: MultiThreadedEventLoopGroup!
    private var loop: EventLoop { group.next() }

    override func setUp() {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    }

    override func tearDown() async throws {
        try await group.shutdownGracefully()
    }

    private func nextOffer(
        _ auth: NIOSSHClientUserAuthenticationDelegate,
        _ methods: NIOSSHAvailableUserAuthenticationMethods
    ) async throws -> NIOSSHUserAuthenticationOffer? {
        let promise = loop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        loop.execute { auth.nextAuthenticationType(availableMethods: methods, nextChallengePromise: promise) }
        return try await promise.futureResult.get()
    }

    private func answer(
        _ auth: KeyboardInteractiveAuthenticator,
        _ challenge: NIOSSHKeyboardInteractiveChallenge
    ) async throws -> [String] {
        let promise = loop.makePromise(of: [String].self)
        loop.execute { auth.respondToKeyboardInteractiveChallenge(challenge, responsePromise: promise) }
        return try await promise.futureResult.get()
    }

    // MARK: - Password / keyboard-interactive

    func testPasswordAndTypedAnswersAreNeverLogged() async throws {
        let lines = CapturedLines()
        let trace = LoginTrace(sink: lines.sink)
        let code = typedCode
        let auth = KeyboardInteractiveAuthenticator(
            username: "deploy", password: password,
            ask: { _, _ in code }, show: { _ in }, trace: trace)

        // Probe, then the server only takes keyboard-interactive (PAM + OTP).
        _ = try await nextOffer(auth, [])
        _ = try await nextOffer(auth, [.publicKey, .keyboardInteractive])
        let responses = try await answer(auth, .init(name: "", instruction: "", prompts: [
            .init(prompt: "Password: ", echo: false),
            .init(prompt: "Verification code: ", echo: false),
        ]))
        XCTAssertEqual(responses, [password, typedCode], "the login itself still gets both answers")

        // Server rejects; nothing left to try.
        do {
            _ = try await nextOffer(auth, [.publicKey, .keyboardInteractive])
            XCTFail("expected rejection")
        } catch SSHLoginError.rejected {}

        let text = lines.text
        XCTAssertFalse(text.contains(password), "stored password leaked into the log:\n\(text)")
        XCTAssertFalse(text.contains(typedCode), "typed answer leaked into the log:\n\(text)")

        // ...while still saying what happened.
        XCTAssertTrue(text.contains("server accepts [publickey, keyboard-interactive]"), text)
        XCTAssertTrue(text.contains("offering keyboard-interactive"), text)
        XCTAssertTrue(text.contains("\"Password: \" (hidden): answered with the vault password"), text)
        XCTAssertTrue(text.contains("\"Verification code: \" (hidden): asking the user"), text)
        XCTAssertTrue(lines.errors.contains { $0.contains("server rejected [keyboard-interactive]") }, text)
        XCTAssertTrue(lines.all.allSatisfy { $0.hasPrefix("[\(trace.id) +") }, "every line carries the attempt id")
    }

    func testPasswordOfferIsLoggedWithoutThePassword() async throws {
        let lines = CapturedLines()
        let auth = KeyboardInteractiveAuthenticator(
            username: "deploy", password: password,
            ask: { _, _ in nil }, show: { _ in }, trace: LoginTrace(sink: lines.sink))

        _ = try await nextOffer(auth, [])
        let offer = try await nextOffer(auth, [.password])
        guard case .password = offer?.offer else { return XCTFail("expected a password offer") }

        XCTAssertTrue(lines.text.contains("offering password (stored in vault)"), lines.text)
        XCTAssertFalse(lines.text.contains(password), lines.text)
    }

    func testNoUsableMethodIsAnError() async throws {
        let lines = CapturedLines()
        let auth = KeyboardInteractiveAuthenticator(
            username: "deploy", password: nil,
            ask: { _, _ in nil }, show: { _ in }, trace: LoginTrace(sink: lines.sink))

        _ = try await nextOffer(auth, [])
        do {
            _ = try await nextOffer(auth, [.publicKey])
            XCTFail("expected failure")
        } catch SSHLoginError.noUsableMethod {}
        XCTAssertTrue(lines.errors.contains { $0.contains("server accepts none of the methods") }, lines.text)
    }

    // MARK: - Formatting

    func testBeginFlagsSuspiciousUsernames() {
        let lines = CapturedLines()
        let trace = LoginTrace(sink: lines.sink)
        trace.begin("SSH", host: "example.com", port: 22, username: "deploy\t", method: "publickey")
        XCTAssertTrue(lines.text.contains("as \"deploy\\t\""), "control characters are made visible: \(lines.text)")
        XCTAssertTrue(lines.errors.contains { $0.contains("leading or trailing whitespace") }, lines.text)
    }

    func testDescribeMethods() {
        XCTAssertEqual(LoginTrace.describe(NIOSSHAvailableUserAuthenticationMethods()), "(none)")
        XCTAssertEqual(LoginTrace.describe([.password, .publicKey]), "publickey, password")
    }
}

final class LoginLogBufferTests: XCTestCase {
    func testKeepsOnlyTheNewestLines() {
        let buffer = LoginLogBuffer(capacity: 3)
        for i in 0..<5 { buffer.append(level: .info, line: "[id\(i) +0ms] line \(i)") }
        XCTAssertEqual(buffer.entries.map(\.line), ["[id2 +0ms] line 2", "[id3 +0ms] line 3", "[id4 +0ms] line 4"])
        XCTAssertEqual(Set(buffer.entries.map(\.id)).count, 3, "ids stay unique after trimming")
        buffer.removeAll()
        XCTAssertTrue(buffer.entries.isEmpty)
    }

    func testAttemptIDIsReadFromThePrefix() {
        func entry(_ line: String) -> LoginLogEntry { .init(id: 0, date: Date(), level: .info, line: line) }
        XCTAssertEqual(entry("[1c6b2ecf +12ms] tcp: connecting").attemptID, "1c6b2ecf")
        XCTAssertNil(entry("[-] credential could not be decrypted").attemptID)
        XCTAssertNil(entry("no prefix").attemptID)
    }

    func testTraceLinesCarryTheirAttemptID() {
        let buffer = LoginLogBuffer()
        let trace = LoginTrace(sink: { buffer.append(level: $0, line: $1) })
        trace.info("hello")
        XCTAssertEqual(buffer.entries.first?.attemptID, trace.id)
    }
}
