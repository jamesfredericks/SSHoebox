import XCTest
import Crypto
import NIOCore
import NIOPosix
@testable import NIOSSH
@testable import SSHoeboxCore

/// Verbose (`ssh -v`) login logging, end to end against an in-process SSH server.
@MainActor
final class VerboseLoginLogTests: XCTestCase {
    private let secret = "s3cret-Password-123"
    private var server: InProcessSSHServer!

    override func setUp() async throws {
        UserDefaults.standard.removeObject(forKey: LoginTrace.verboseDefaultsKey)  // default: on
        server = try await InProcessSSHServer.start(password: secret, banner: "Authorized use only\n")
    }

    override func tearDown() async throws {
        UserDefaults.standard.removeObject(forKey: LoginTrace.verboseDefaultsKey)
        try await server?.stop()
    }

    /// Logs in with `password`, and returns the attempt's lines once it has ended (the server
    /// refuses the session channel, so even a successful login ends straight after auth).
    private func login(password: String) async throws -> [LoginLogEntry] {
        let manager = SSHSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
        await manager.connect(host: "127.0.0.1", port: server.port, username: "deploy", password: password)
        let attempt = try XCTUnwrap(manager.lastLoginAttemptID)

        var lines: [LoginLogEntry] = []
        for _ in 0..<250 {
            lines = LoginLogBuffer.shared.entries.filter { $0.attemptID == attempt }
            if lines.contains(where: { $0.line.contains("] failed: ") || $0.line.contains("login complete") }) { break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        manager.disconnect()
        return lines
    }

    func testVerboseLogShowsTheProtocolButNeverThePassword() async throws {
        let entries = try await login(password: secret)
        let text = entries.map(\.line).joined(separator: "\n")

        XCTAssertFalse(text.contains(secret), "password leaked into the verbose log:\n\(text)")

        for expected in [
            "tcp: connected to [IPv4]127.0.0.1/127.0.0.1:\(server.port)",
            "→ version \"SSH-2.0-",
            "← version \"SSH-2.0-",
            "→ SSH_MSG_KEXINIT",
            "← SSH_MSG_KEXINIT",
            "  kex algorithms: ",
            "kex: algorithm ",
            "kex: cipher ",
            "← SSH_MSG_KEX_ECDH_REPLY host key ssh-ed25519",
            "host key: server presented ssh-ed25519 SHA256:",
            "→ SSH_MSG_NEWKEYS",
            "→ SSH_MSG_SERVICE_REQUEST ssh-userauth",
            "← SSH_MSG_USERAUTH_BANNER \"Authorized use only\\n\"",
            "→ SSH_MSG_USERAUTH_REQUEST user \"deploy\" service ssh-connection method none",
            "← SSH_MSG_USERAUTH_FAILURE can continue: password",
            "→ SSH_MSG_USERAUTH_REQUEST user \"deploy\" service ssh-connection method password (not logged)",
            "← SSH_MSG_USERAUTH_SUCCESS",
            "auth: SUCCESS",
            "→ SSH_MSG_CHANNEL_OPEN session",
        ] {
            XCTAssertTrue(text.contains(expected), "missing \(expected.debugDescription) in:\n\(text)")
        }
        XCTAssertTrue(entries.contains { $0.level == .debug && $0.line.contains("SSH_MSG_KEXINIT") },
                      "protocol lines are debug level")
    }

    func testWrongPasswordShowsTheRejection() async throws {
        let entries = try await login(password: "wrong-guess-456")
        let text = entries.map(\.line).joined(separator: "\n")
        XCTAssertFalse(text.contains("wrong-guess-456"), text)
        XCTAssertEqual(text.components(separatedBy: "← SSH_MSG_USERAUTH_FAILURE can continue: password").count - 1, 2,
                       "rejected once for 'none' and once for the password:\n\(text)")
        XCTAssertTrue(entries.contains { $0.level == .error && $0.line.contains("failed: ") }, text)
    }

    func testVerboseOffKeepsOnlyTheSummary() async throws {
        UserDefaults.standard.set(false, forKey: LoginTrace.verboseDefaultsKey)
        let entries = try await login(password: secret)
        XCTAssertFalse(entries.contains { $0.level == .debug }, entries.map(\.line).joined(separator: "\n"))
        XCTAssertTrue(entries.contains { $0.line.contains("auth: SUCCESS") })
    }
}

/// The redaction of messages a password login doesn't exercise.
final class SSHMessageRedactionTests: XCTestCase {
    private func lines(_ message: SSHMessage) -> String {
        message.redactedDebugLines.joined(separator: "\n")
    }

    func testSecretsAreLeftOut() {
        let answers = lines(.userAuthInfoResponse(.init(responses: ["hunter2", "918273"])))
        XCTAssertEqual(answers, "SSH_MSG_USERAUTH_INFO_RESPONSE 2 answer(s) (not logged)")

        let env = lines(.channelRequest(.init(recipientChannel: 0, type: .env("API_TOKEN", "tok-abc"), wantReply: false)))
        XCTAssertTrue(env.contains("API_TOKEN") && !env.contains("tok-abc"), env)

        let exec = lines(.channelRequest(.init(recipientChannel: 0, type: .exec("mysql -pSECRET"), wantReply: true)))
        XCTAssertFalse(exec.contains("SECRET"), exec)
    }

    func testChannelTrafficIsNeverReported() {
        let allocator = ByteBufferAllocator()
        XCTAssertTrue(SSHMessage.channelData(.init(recipientChannel: 0, data: allocator.buffer(string: "sudo pw"))).redactedDebugLines.isEmpty)
        XCTAssertTrue(SSHMessage.channelExtendedData(.init(recipientChannel: 0, dataTypeCode: .stderr,
                                                           data: allocator.buffer(string: "x"))).redactedDebugLines.isEmpty)
        XCTAssertTrue(SSHMessage.channelWindowAdjust(.init(recipientChannel: 0, bytesToAdd: 1)).redactedDebugLines.isEmpty)
    }

    func testPromptsAndServerTextAreShownEscaped() {
        let request = lines(.userAuthInfoRequest(.init(name: "", instruction: "", languageTag: "",
                                                       prompts: [.init(prompt: "Verification code: ", echo: false)])))
        XCTAssertTrue(request.contains("prompt 1: \"Verification code: \" no echo"), request)

        let disconnect = lines(.disconnect(.init(reason: 14, description: "bye\r\n\u{1B}[31m", tag: "")))
        XCTAssertEqual(disconnect, "SSH_MSG_DISCONNECT reason 14 (no more auth methods available) \"bye\\r\\n\\u{1b}[31m\"")
    }
}

/// A NIOSSH server on 127.0.0.1 that accepts one password and refuses every channel.
final class InProcessSSHServer: @unchecked Sendable {
    let port: Int
    private let channel: Channel
    private let group: MultiThreadedEventLoopGroup

    private init(port: Int, channel: Channel, group: MultiThreadedEventLoopGroup) {
        self.port = port
        self.channel = channel
        self.group = group
    }

    static func start(password: String, banner: String) async throws -> InProcessSSHServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let hostKey = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey())
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { child in
                child.eventLoop.makeCompletedFuture {
                    let configuration = SSHServerConfiguration(
                        hostKeys: [hostKey],
                        userAuthDelegate: PasswordChecker(password: password),
                        banner: .init(message: banner, languageTag: "en"))
                    try child.pipeline.syncOperations.addHandler(NIOSSHHandler(
                        role: .server(configuration), allocator: child.allocator, inboundChildChannelInitializer: nil))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return InProcessSSHServer(port: channel.localAddress!.port!, channel: channel, group: group)
    }

    func stop() async throws {
        try await channel.close()
        try await group.shutdownGracefully()
    }

    private final class PasswordChecker: NIOSSHServerUserAuthenticationDelegate, @unchecked Sendable {
        let password: String
        init(password: String) { self.password = password }

        var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods { .password }

        func requestReceived(request: NIOSSHUserAuthenticationRequest,
                             responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
            if case .password(let attempt) = request.request, attempt.password == password {
                responsePromise.succeed(.success)
            } else {
                responsePromise.succeed(.failure)
            }
        }
    }
}
