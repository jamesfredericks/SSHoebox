import XCTest
import Darwin
import Crypto
import NIOCore
import NIOPosix
import NIOSSH
import Citadel
@testable import SSHoeboxCore

final class SSHAgentClientTests: XCTestCase {
    var directory: String!
    var socketPath: String!
    var agent: FakeExternalAgent!

    override func setUpWithError() throws {
        // sun_path is limited to 104 bytes on macOS, so keep the path short.
        directory = "/tmp/sshoebox-ext-\(UUID().uuidString.prefix(8))"
        socketPath = directory + "/agent.sock"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        agent = try FakeExternalAgent(path: socketPath)
    }

    override func tearDown() {
        agent?.stop()
        try? FileManager.default.removeItem(atPath: directory)
    }

    // MARK: - Client

    func testListsIdentities() throws {
        let ed = agent.addEd25519(comment: "James SSH Key")
        let p256 = agent.addP256(comment: "")

        let identities = try SSHAgentClient(socketPath: socketPath).identities()

        XCTAssertEqual(identities.map(\.keyBlob), [ed.blob, p256.blob])
        XCTAssertEqual(identities[0].comment, "James SSH Key")
        XCTAssertEqual(identities[0].algorithm, "ssh-ed25519")
        XCTAssertEqual(identities[1].algorithm, "ecdsa-sha2-nistp256")
        XCTAssertTrue(identities[0].openSSHPublicKey.hasSuffix(" James SSH Key"))
        XCTAssertTrue(identities[0].fingerprint.hasPrefix("SHA256:"))
    }

    func testSignReturnsVerifiableSignature() throws {
        let key = agent.addEd25519(comment: "k")
        let data = Data("to be signed".utf8)

        let blob = try SSHAgentClient(socketPath: socketPath).sign(keyBlob: key.blob, data: data)

        let (name, rest) = try XCTUnwrap(SSHAgentKeyReference.readString(blob, at: blob.startIndex))
        XCTAssertEqual(String(decoding: name, as: UTF8.self), "ssh-ed25519")
        let (signature, _) = try XCTUnwrap(SSHAgentKeyReference.readString(blob, at: rest))
        XCTAssertTrue(key.ed25519!.publicKey.isValidSignature(signature, for: data))
    }

    func testRefusedSignIsReported() throws {
        let key = agent.addEd25519(comment: "k")
        agent.refuseSigning = true
        XCTAssertThrowsError(try SSHAgentClient(socketPath: socketPath).sign(keyBlob: key.blob, data: Data())) {
            XCTAssertEqual($0 as? SSHAgentClientError, .signingRefused)
        }
    }

    func testUnansweredSignTimesOut() throws {
        let key = agent.addEd25519(comment: "k")
        agent.signDelay = 3
        let client = SSHAgentClient(socketPath: socketPath, timeout: 1)
        XCTAssertThrowsError(try client.sign(keyBlob: key.blob, data: Data())) {
            XCTAssertEqual($0 as? SSHAgentClientError, .timedOut)
        }
    }

    func testMissingSocketMeansAgentNotRunning() {
        let path = directory + "/nothing.sock"
        XCTAssertThrowsError(try SSHAgentClient(socketPath: path).identities()) {
            XCTAssertEqual($0 as? SSHAgentClientError, .agentNotRunning(path))
        }
    }

    func testRefusesSSHoeboxOwnAgent() async throws {
        let ownPath = directory + "/own.sock"
        let server = SSHAgentServer(socketPath: ownPath, delegate: MockAgentDelegate())
        try await server.start()
        defer { Task { try? await server.stop() } }

        XCTAssertThrowsError(try SSHAgentClient(socketPath: ownPath).identities()) {
            XCTAssertEqual($0 as? SSHAgentClientError, .ownAgent)
        }
        // A symlink to it is the same socket.
        let link = directory + "/link.sock"
        XCTAssertEqual(symlink(ownPath, link), 0)
        XCTAssertThrowsError(try SSHAgentClient(socketPath: link).identities()) {
            XCTAssertEqual($0 as? SSHAgentClientError, .ownAgent)
        }
    }

    // MARK: - Key reference

    func testReferenceRoundTripsAndParses() throws {
        let key = agent.addEd25519(comment: "James SSH Key")
        let identity = SSHAgentIdentity(keyBlob: key.blob, comment: "James SSH Key")
        let reference = SSHAgentKeyReference(socketPath: socketPath, identity: identity)

        let decoded = try SSHAgentKeyReference.decode(try reference.encoded())
        XCTAssertEqual(decoded, reference)
        XCTAssertEqual(decoded.keyBlob, key.blob)
        XCTAssertEqual(decoded.algorithm, "ssh-ed25519")
        XCTAssertEqual(decoded.comment, "James SSH Key")
        XCTAssertEqual(decoded.fingerprint, identity.fingerprint)
    }

    func testReferenceRejectsMismatchedTypeName() {
        // The line claims ECDSA but the blob is Ed25519.
        let line = TestKeys.ed25519Public.replacingOccurrences(of: "ssh-ed25519", with: "ecdsa-sha2-nistp256")
        XCTAssertNil(SSHAgentKeyReference(socketPath: socketPath, publicKey: line).keyBlob)
    }

    func testPublicKeyMatchesAgentBlob() throws {
        let reference = SSHAgentKeyReference(socketPath: socketPath, publicKey: TestKeys.ed25519Public)
        let key = try AgentBackedKey.privateKey(for: reference)
        let expected = TestKeys.ed25519Public.split(separator: " ").prefix(2).joined(separator: " ")
        XCTAssertEqual(String(openSSHPublicKey: key.publicKey), expected)
    }

    // MARK: - Pre-connect check

    @MainActor
    func testCheckedKeyRequiresAgentToOfferIt() async throws {
        _ = agent.addEd25519(comment: "other")
        let reference = SSHAgentKeyReference(socketPath: socketPath, publicKey: TestKeys.ed25519Public)
        do {
            _ = try await AgentBackedKey.checkedPrivateKey(for: reference)
            XCTFail("Expected keyNotFound")
        } catch {
            XCTAssertEqual(error as? SSHAgentClientError, .keyNotFound(reference.fingerprint))
        }
    }

    @MainActor
    func testCheckedKeyRejectsRSA() async throws {
        let reference = SSHAgentKeyReference(socketPath: socketPath, publicKey: TestKeys.rsaPublic)
        do {
            _ = try await AgentBackedKey.checkedPrivateKey(for: reference)
            XCTFail("Expected unsupportedKeyType")
        } catch {
            XCTAssertEqual(error as? SSHAgentClientError, .unsupportedKeyType("ssh-rsa"))
        }
        XCTAssertEqual(agent.requestCount, 0, "Unsupported keys shouldn't reach the agent")
    }

    // MARK: - End to end

    func testLogsInWithAgentEd25519Key() async throws {
        let key = agent.addEd25519(comment: "k")
        try await assertLogin(with: key, succeeds: true)
        XCTAssertEqual(agent.signCount, 1)
    }

    func testLogsInWithAgentP256Key() async throws {
        let key = agent.addP256(comment: "k")
        try await assertLogin(with: key, succeeds: true)
        XCTAssertEqual(agent.signCount, 1)
    }

    func testLoginFailsWhenServerDoesNotAuthorizeKey() async throws {
        let key = agent.addEd25519(comment: "k")
        let other = agent.addEd25519(comment: "other")
        try await assertLogin(with: key, authorizedKey: other, succeeds: false)
    }

    func testLoginFailsWhenAgentRefuses() async throws {
        let key = agent.addEd25519(comment: "k")
        agent.refuseSigning = true
        try await assertLogin(with: key, succeeds: false)
    }

    func testNoApprovalPromptWhenServerDoesNotTakeKeys() async throws {
        let key = agent.addEd25519(comment: "k")
        try await assertLogin(with: key, serverMethods: .password, succeeds: false)
        XCTAssertEqual(agent.signCount, 0, "The agent mustn't be asked to sign for a server that won't accept it")
    }

    private func assertLogin(
        with key: FakeExternalAgent.Key,
        authorizedKey: FakeExternalAgent.Key? = nil,
        serverMethods: NIOSSHAvailableUserAuthenticationMethods = .publicKey,
        succeeds: Bool
    ) async throws {
        let authorized = try NIOSSHPublicKey(openSSHPublicKey: (authorizedKey ?? key).openSSHLine)
        let serverGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let (server, port) = try await startServer(
            delegate: AuthorizedKeyDelegate(key: authorized, methods: serverMethods), group: serverGroup)

        let reference = SSHAgentKeyReference(socketPath: socketPath, publicKey: key.openSSHLine)
        let privateKey = try AgentBackedKey.privateKey(for: reference)
        let clientGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        var settings = SSHClientSettings(
            host: "127.0.0.1",
            port: port,
            authenticationMethod: { .custom(AgentKeyAuthenticator(username: "james", privateKey: privateKey)) },
            hostKeyValidator: .acceptAnything()
        )
        settings.group = clientGroup

        do {
            let client = try await SSHClient.connect(to: settings)
            try? await client.close()
            XCTAssertTrue(succeeds, "Login should have been rejected")
        } catch {
            XCTAssertFalse(succeeds, "Login failed: \(error)")
        }
        try? await server.close()
        try? await clientGroup.shutdownGracefully()
        try? await serverGroup.shutdownGracefully()
    }

    /// Citadel's server needs a fixed port, so try a few random ones.
    private func startServer(
        delegate: NIOSSHServerUserAuthenticationDelegate,
        group: MultiThreadedEventLoopGroup
    ) async throws -> (SSHServer, Int) {
        var lastError: Error?
        for _ in 0..<10 {
            let port = Int.random(in: 40_000..<60_000)
            do {
                let server = try await SSHServer.host(
                    host: "127.0.0.1", port: port,
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    authenticationDelegate: delegate, group: group)
                return (server, port)
            } catch {
                lastError = error
            }
        }
        throw lastError!
    }
}

/// Accepts public-key logins (already signature-checked by NIOSSH) for one key.
private final class AuthorizedKeyDelegate: NIOSSHServerUserAuthenticationDelegate {
    let key: NIOSSHPublicKey
    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods

    init(key: NIOSSHPublicKey, methods: NIOSSHAvailableUserAuthenticationMethods) {
        self.key = key
        self.supportedAuthenticationMethods = methods
    }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        if case .publicKey(let offer) = request.request, offer.publicKey == key {
            responsePromise.succeed(.success)
        } else {
            responsePromise.succeed(.failure)
        }
    }
}

// MARK: - Fake external agent

/// A password-manager style agent on its own thread: blocking Unix socket, real signatures,
/// and switches to refuse or delay signing.
final class FakeExternalAgent: @unchecked Sendable {
    struct Key {
        let blob: Data
        let algorithm: String
        var ed25519: Curve25519.Signing.PrivateKey?
        var p256: P256.Signing.PrivateKey?
        var comment: String

        var openSSHLine: String { "\(algorithm) \(blob.base64EncodedString())" }
    }

    private let path: String
    private let listener: Int32
    private let lock = NSLock()
    private var keys: [Key] = []
    private var _refuseSigning = false
    private var _signDelay: UInt32 = 0
    private var _requestCount = 0
    private var _signCount = 0

    var refuseSigning: Bool {
        get { lock.withLock { _refuseSigning } }
        set { lock.withLock { _refuseSigning = newValue } }
    }
    var signDelay: UInt32 {
        get { lock.withLock { _signDelay } }
        set { lock.withLock { _signDelay = newValue } }
    }
    var requestCount: Int { lock.withLock { _requestCount } }
    var signCount: Int { lock.withLock { _signCount } }

    init(path: String) throws {
        self.path = path
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(path.utf8)) }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(listener, 8) == 0 else { throw POSIXError(.EADDRINUSE) }
        Thread { [weak self] in self?.acceptLoop() }.start()
    }

    func stop() {
        shutdown(listener, SHUT_RDWR)
        close(listener)
        unlink(path)
    }

    @discardableResult
    func addEd25519(comment: String) -> Key {
        let privateKey = Curve25519.Signing.PrivateKey()
        let blob = Self.string("ssh-ed25519") + Self.string(privateKey.publicKey.rawRepresentation)
        let key = Key(blob: blob, algorithm: "ssh-ed25519", ed25519: privateKey, comment: comment)
        lock.withLock { keys.append(key) }
        return key
    }

    @discardableResult
    func addP256(comment: String) -> Key {
        let privateKey = P256.Signing.PrivateKey()
        let blob = Self.string("ecdsa-sha2-nistp256") + Self.string("nistp256")
            + Self.string(privateKey.publicKey.x963Representation)
        let key = Key(blob: blob, algorithm: "ecdsa-sha2-nistp256", p256: privateKey, comment: comment)
        lock.withLock { keys.append(key) }
        return key
    }

    private func acceptLoop() {
        while true {
            let connection = accept(listener, nil, nil)
            guard connection >= 0 else { return }
            var noSigPipe: Int32 = 1
            setsockopt(connection, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            serve(connection)
            close(connection)
        }
    }

    private func serve(_ connection: Int32) {
        while let request = readFrame(connection) {
            lock.withLock { _requestCount += 1 }
            write(connection, frame: reply(to: request))
        }
    }

    private func reply(to request: Data) -> Data {
        guard let type = request.first else { return Data([5]) }
        switch type {
        case 11: // REQUEST_IDENTITIES
            let snapshot = lock.withLock { keys }
            var reply = Data([12]) + Self.uint32(snapshot.count)
            for key in snapshot { reply += Self.string(key.blob) + Self.string(key.comment) }
            return reply
        case 13: // SIGN_REQUEST
            lock.withLock { _signCount += 1 }
            let body = request.dropFirst()
            guard let (blob, rest) = SSHAgentKeyReference.readString(Data(body), at: 0),
                  let (data, _) = SSHAgentKeyReference.readString(Data(body), at: rest),
                  let key = lock.withLock({ keys.first { $0.blob == blob } }) else { return Data([5]) }
            let (refuse, delay) = lock.withLock { (_refuseSigning, _signDelay) }
            if delay > 0 { sleep(delay) }
            if refuse { return Data([5]) }
            return Data([14]) + Self.string(Self.signature(key: key, data: data))
        default:
            return Data([5])
        }
    }

    private static func signature(key: Key, data: Data) -> Data {
        if let ed = key.ed25519 {
            return string("ssh-ed25519") + string(try! ed.signature(for: data))
        }
        let raw = try! key.p256!.signature(for: data).rawRepresentation
        let inner = mpint(raw.prefix(32)) + mpint(raw.suffix(32))
        return string("ecdsa-sha2-nistp256") + string(inner)
    }

    private func readFrame(_ connection: Int32) -> Data? {
        guard let header = readExactly(connection, 4) else { return nil }
        let length = header.reduce(0) { $0 << 8 | Int($1) }
        return readExactly(connection, length)
    }

    private func readExactly(_ connection: Int32, _ count: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let read = bytes[offset...].withUnsafeMutableBytes { recv(connection, $0.baseAddress, $0.count, 0) }
            guard read > 0 else { return nil }
            offset += read
        }
        return Data(bytes)
    }

    private func write(_ connection: Int32, frame body: Data) {
        let frame = Self.uint32(body.count) + body
        _ = frame.withUnsafeBytes { send(connection, $0.baseAddress, $0.count, 0) }
    }

    static func uint32(_ value: Int) -> Data {
        withUnsafeBytes(of: UInt32(value).bigEndian) { Data($0) }
    }

    static func string(_ value: String) -> Data { string(Data(value.utf8)) }

    static func string(_ value: Data) -> Data { uint32(value.count) + value }

    /// An SSH mpint of a positive big-endian integer.
    static func mpint(_ value: Data) -> Data {
        var bytes = Data(value.drop { $0 == 0 })
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        return string(bytes)
    }
}
