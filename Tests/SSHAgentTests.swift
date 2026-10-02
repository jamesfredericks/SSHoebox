import XCTest
import Darwin
@testable import SSHoeboxCore

final class SSHAgentTests: XCTestCase {
    var directory: String!
    var socketPath: String!
    var delegate: MockAgentDelegate!
    var server: SSHAgentServer?

    override func setUpWithError() throws {
        // sun_path is limited to 104 bytes on macOS, so keep the path short.
        directory = "/tmp/sshoebox-test-\(UUID().uuidString.prefix(8))"
        socketPath = directory + "/agent.sock"
        delegate = MockAgentDelegate()
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? await server?.stop()
        server = nil
        try? FileManager.default.removeItem(atPath: directory)
    }

    private func startServer() async throws -> SSHAgentServer {
        let server = SSHAgentServer(socketPath: socketPath, delegate: delegate)
        try await server.start()
        self.server = server
        return server
    }

    // MARK: - Framing

    func testListsIdentities() async throws {
        _ = try await startServer()
        let client = try AgentTestClient(path: socketPath)
        try client.send(message: [SSHAgentMessage.SSH2_AGENTC_REQUEST_IDENTITIES])

        var reply = try client.readFrame()
        XCTAssertEqual(reply.removeFirst(), SSHAgentMessage.SSH2_AGENT_IDENTITIES_ANSWER)
        XCTAssertEqual(reply.prefix(4), Data([0, 0, 0, 1]), "One identity expected")
    }

    func testOversizedFrameDropsConnection() async throws {
        _ = try await startServer()
        let client = try AgentTestClient(path: socketPath)
        // Claim a ~4 GiB message; the agent must hang up instead of buffering it.
        try client.send(raw: Data([0xFF, 0xFF, 0xFF, 0xFF, SSHAgentMessage.SSH2_AGENTC_REQUEST_IDENTITIES]))
        XCTAssertTrue(try client.readUntilClosed().isEmpty, "Connection should close without a reply")
    }

    func testLargestAllowedFrameIsAccepted() async throws {
        _ = try await startServer()
        let client = try AgentTestClient(path: socketPath)
        // An unknown message type padded to exactly the limit gets a normal failure reply.
        var message = Data([200])
        message.append(Data(count: SSHAgentProtocol.maxMessageLength - 1))
        try client.send(message: message)
        XCTAssertEqual(try client.readFrame(), Data([SSHAgentMessage.SSH_AGENT_FAILURE]))
    }

    // MARK: - Socket security

    private func mode(of path: String) -> mode_t {
        var info = stat()
        XCTAssertEqual(lstat(path, &info), 0)
        return info.st_mode & 0o7777
    }

    func testSocketAndDirectoryAreOwnerOnly() async throws {
        XCTAssertEqual(chmod(directory, 0o755), 0)
        _ = try await startServer()
        XCTAssertEqual(mode(of: directory), 0o700)
        XCTAssertEqual(mode(of: socketPath), 0o600)
    }

    func testCreatesMissingSocketDirectory() async throws {
        try FileManager.default.removeItem(atPath: directory)
        _ = try await startServer()
        XCTAssertEqual(mode(of: directory), 0o700)
        XCTAssertNoThrow(try AgentTestClient(path: socketPath))
    }

    func testReplacesStaleSocket() async throws {
        let first = try await startServer()
        try await first.stop()
        // Simulate a crash that left the socket file behind.
        let stale = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { close(stale) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(socketPath.utf8)) }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(stale, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        XCTAssertEqual(bound, 0)

        _ = try await startServer()
        XCTAssertNoThrow(try AgentTestClient(path: socketPath))
    }

    func testRefusesToDeleteNonSocketFile() async throws {
        FileManager.default.createFile(atPath: socketPath, contents: Data("keep me".utf8))
        let server = SSHAgentServer(socketPath: socketPath, delegate: delegate)
        do {
            try await server.start()
            XCTFail("start() should refuse to replace a regular file")
        } catch SSHAgentError.socketPathInUse {
            // expected
        }
        XCTAssertEqual(FileManager.default.contents(atPath: socketPath), Data("keep me".utf8))
    }

    // MARK: - Ordering

    func testRepliesFollowRequestOrder() async throws {
        _ = try await startServer()
        let client = try AgentTestClient(path: socketPath)
        // A slow sign followed by a fast identities request, sent in one write.
        let slowSign = AgentTestClient.signRequest(key: MockAgentDelegate.keyBlob, data: Data("slow-data".utf8))
        try client.send(raw: AgentTestClient.encodeString(slowSign)
                        + AgentTestClient.encodeString(Data([SSHAgentMessage.SSH2_AGENTC_REQUEST_IDENTITIES]))
                        + AgentTestClient.encodeString(Data([200])))

        XCTAssertEqual(try client.readFrame().first, SSHAgentMessage.SSH2_AGENT_SIGN_RESPONSE,
                       "The slow sign must be answered before the identities request behind it")
        XCTAssertEqual(try client.readFrame().first, SSHAgentMessage.SSH2_AGENT_IDENTITIES_ANSWER)
        XCTAssertEqual(try client.readFrame(), Data([SSHAgentMessage.SSH_AGENT_FAILURE]))
    }

    func testSignResponseCarriesSignature() async throws {
        _ = try await startServer()
        let client = try AgentTestClient(path: socketPath)
        try client.send(message: AgentTestClient.signRequest(key: MockAgentDelegate.keyBlob, data: Data("abc".utf8)))
        XCTAssertEqual(try client.readFrame(),
                       Data([SSHAgentMessage.SSH2_AGENT_SIGN_RESPONSE])
                       + AgentTestClient.encodeString(MockAgentDelegate.signature + Data("abc".utf8)))
    }

    func testFloodOfPipelinedRequestsDropsConnection() async throws {
        delegate.slowSignDelay = 2_000_000_000
        _ = try await startServer()
        let client = try AgentTestClient(path: socketPath)
        let slowSign = AgentTestClient.encodeString(
            AgentTestClient.signRequest(key: MockAgentDelegate.keyBlob, data: Data("slow".utf8)))
        let identities = AgentTestClient.encodeString(Data([SSHAgentMessage.SSH2_AGENTC_REQUEST_IDENTITIES]))
        var flood = slowSign
        for _ in 0..<(SSHAgentHandler.maxQueuedRequests + 8) { flood.append(identities) }
        try client.send(raw: flood)
        XCTAssertTrue(try client.readUntilClosed().isEmpty,
                      "Overflowing the request queue should drop the connection")
    }
}

// MARK: - Test doubles

final class MockAgentDelegate: SSHAgentDelegate {
    static let keyBlob = AgentTestClient.encodeString("ssh-ed25519") + AgentTestClient.encodeString(Data(repeating: 7, count: 32))
    static let signature = Data("signature".utf8)

    /// Delay applied to sign requests whose data starts with "slow".
    var slowSignDelay: UInt64 = 300_000_000

    func getIdentities() async -> [(key: Data, comment: String)] {
        [(Self.keyBlob, "test@example")]
    }

    func sign(key: Data, data: Data, flags: UInt32) async throws -> Data {
        guard key == Self.keyBlob else { throw SSHAgentError.invalidMessage }
        if data.starts(with: Data("slow".utf8)) {
            try await Task.sleep(nanoseconds: slowSignDelay)
        }
        return Self.signature + data
    }
}

/// Minimal blocking agent client over a raw Unix socket.
final class AgentTestClient {
    let fd: Int32

    init(path: String) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            let bytes = Array(path.utf8.prefix(raw.count - 1))
            raw.copyBytes(from: bytes)
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let code = errno
            close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
    }

    deinit { close(fd) }

    static func encodeString(_ string: String) -> Data { encodeString(Data(string.utf8)) }

    static func encodeString(_ data: Data) -> Data {
        var length = UInt32(data.count).bigEndian
        return Data(bytes: &length, count: 4) + data
    }

    static func signRequest(key: Data, data: Data, flags: UInt32 = 0) -> Data {
        var flagsBE = flags.bigEndian
        return Data([SSHAgentMessage.SSH2_AGENTC_SIGN_REQUEST]) + encodeString(key) + encodeString(data)
            + Data(bytes: &flagsBE, count: 4)
    }

    func send(raw data: Data) throws {
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                guard written > 0 else { throw POSIXError(.EPIPE) }
                offset += written
            }
        }
    }

    func send(message: Data) throws {
        try send(raw: Self.encodeString(message))
    }

    func send(message bytes: [UInt8]) throws {
        try send(message: Data(bytes))
    }

    /// Reads exactly `count` bytes, or returns what arrived before EOF.
    private func read(count: Int) throws -> Data {
        var data = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while data.count < count {
            let n = Darwin.read(fd, &chunk, min(chunk.count, count - data.count))
            if n == 0 { break }
            guard n > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            data.append(chunk, count: n)
        }
        return data
    }

    func readFrame() throws -> Data {
        let header = try read(count: 4)
        guard header.count == 4 else { throw POSIXError(.ECONNRESET) }
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        return try read(count: length)
    }

    /// Reads until the agent closes the connection and returns everything received.
    func readUntilClosed() throws -> Data {
        try read(count: Int.max / 2)
    }
}
