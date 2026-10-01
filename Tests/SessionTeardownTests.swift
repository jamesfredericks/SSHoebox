import XCTest
import Network
@testable import SSHoeboxCore

/// Checks that SSH sessions close their TCP connection when they end, using a local
/// TCP listener as a stand-in server. None of these tests completes an SSH handshake.
@MainActor
final class SessionTeardownTests: XCTestCase {
    var server: FakeTCPServer!
    var manager: SSHSessionManager!

    override func setUp() async throws {
        manager = SSHSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: try DatabaseManager(inMemory: true))
    }

    override func tearDown() async throws {
        manager?.disconnect()
        server?.stop()
    }

    private func connect() async {
        await manager.connect(host: "127.0.0.1", port: server.port, username: "user", password: "password")
    }

    // Each wait is well under Citadel's 10s login timeout, so a pass means the socket was
    // closed by teardown rather than by the timeout.

    func testDisconnectDuringHandshakeClosesSocket() async throws {
        server = try await FakeTCPServer.start()
        let accepted = server.expectAccept(count: 1)
        let closed = server.expectPeerClose(connection: 0)

        await connect()
        await fulfillment(of: [accepted], timeout: 3)
        manager.disconnect()
        await fulfillment(of: [closed], timeout: 3)

        // The abandoned handshake fails once the socket closes; that must not be shown as an error.
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(manager.connectionState, .disconnected)
    }

    func testReconnectClosesPreviousConnection() async throws {
        server = try await FakeTCPServer.start()
        let firstAccepted = server.expectAccept(count: 1)
        let firstClosed = server.expectPeerClose(connection: 0)

        await connect()
        await fulfillment(of: [firstAccepted], timeout: 3)
        await connect()
        await fulfillment(of: [firstClosed], timeout: 3)
        XCTAssertEqual(manager.connectionState, .connecting)
    }

    func testFailedHandshakeClosesSocket() async throws {
        // An unsupported protocol version fails the handshake straight away. (Non-SSH text
        // wouldn't: servers may send other lines before the version line.)
        server = try await FakeTCPServer.start(greeting: Data("SSH-1.5-FakeServer\r\n".utf8))
        let closed = server.expectPeerClose(connection: 0)

        await connect()
        await fulfillment(of: [closed], timeout: 3)
    }
}

/// A loopback TCP listener that accepts connections, optionally sends a greeting, and
/// reports when the client closes its side.
final class FakeTCPServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "FakeTCPServer")
    private let greeting: Data?
    private var connections: [NWConnection] = []
    private var acceptWaiters: [(count: Int, expectation: XCTestExpectation)] = []
    private var closeWaiters: [Int: XCTestExpectation] = [:]
    private var closedConnections: Set<Int> = []
    private var startResumed = false
    private(set) var port: Int = 0

    private init(greeting: Data?) throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        self.greeting = greeting
    }

    static func start(greeting: Data? = nil) async throws -> FakeTCPServer {
        let server = try FakeTCPServer(greeting: greeting)
        try await server.run()
        return server
    }

    private func run() async throws {
        listener.newConnectionHandler = { [unowned self] connection in self.accept(connection) }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            listener.stateUpdateHandler = { [unowned self] state in
                guard !self.startResumed else { return }
                switch state {
                case .ready:
                    self.startResumed = true
                    self.port = Int(self.listener.port?.rawValue ?? 0)
                    continuation.resume()
                case .failed(let error):
                    self.startResumed = true
                    continuation.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: queue)
        }
    }

    func stop() {
        queue.sync {
            connections.forEach { $0.cancel() }
            listener.cancel()
        }
    }

    func expectAccept(count: Int) -> XCTestExpectation {
        let expectation = XCTestExpectation(description: "\(count) connection(s) accepted")
        queue.sync {
            if connections.count >= count { expectation.fulfill() } else { acceptWaiters.append((count, expectation)) }
        }
        return expectation
    }

    func expectPeerClose(connection index: Int) -> XCTestExpectation {
        let expectation = XCTestExpectation(description: "client closed connection \(index)")
        queue.sync {
            if closedConnections.contains(index) { expectation.fulfill() } else { closeWaiters[index] = expectation }
        }
        return expectation
    }

    private func accept(_ connection: NWConnection) {
        let index = connections.count
        connections.append(connection)
        connection.start(queue: queue)
        if let greeting {
            connection.send(content: greeting, completion: .contentProcessed { _ in })
        }
        receive(on: connection, index: index)

        acceptWaiters.removeAll { waiter in
            guard connections.count >= waiter.count else { return false }
            waiter.expectation.fulfill()
            return true
        }
    }

    private func receive(on connection: NWConnection, index: Int) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] _, _, isComplete, error in
            guard let self else { return }
            if isComplete || error != nil {
                self.closedConnections.insert(index)
                self.closeWaiters.removeValue(forKey: index)?.fulfill()
            } else {
                self.receive(on: connection, index: index)
            }
        }
    }
}
