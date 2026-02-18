import Foundation
import Citadel
import Crypto
import NIOSSH
import NIOCore

/// Manages an active SSH PTY session using Citadel.
/// Bridges Citadel's SSH channel I/O to SwiftTerm's terminal input/output.
@MainActor
public class SSHSessionManager: ObservableObject {
    
    public enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case connected
        case failed(String)
    }
    
    @Published public var connectionState: ConnectionState = .disconnected
    
    /// Called when the session ends (disconnect or error).
    public var onDisconnect: (() -> Void)?
    
    private var client: SSHClient?
    private var sessionTask: Task<Void, Never>?
    
    // Stdin pipe: we write to this continuation to send data to the SSH channel
    private var stdinContinuation: AsyncStream<Data>.Continuation?
    
    // We need to keep a reference to the channel handler or channel to write stdin
    private var stdinWriter: TTYStdinWriter?
    private var logBuffer: [Data] = []
    private var currentTerminalSize: (cols: Int, rows: Int) = (80, 24)
    
    public var onOutput: ((Data) -> Void)? {
        didSet {
            if let onOutput = onOutput, !logBuffer.isEmpty {
                for logData in logBuffer {
                    onOutput(logData)
                }
                logBuffer.removeAll()
            }
        }
    }
    
    public init() {}
    
    // MARK: - Connect (Password)
    
    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        password: String,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .passwordBased(username: username, password: password) },
            hostKeyValidator: .acceptAnything()
        )
        await startSession(settings: settings, terminalSize: terminalSize)
    }
    
    // MARK: - Connect (Ed25519 Key)
    
    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        ed25519Key: Curve25519.Signing.PrivateKey,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .ed25519(username: username, privateKey: ed25519Key) },
            hostKeyValidator: .acceptAnything()
        )
        await startSession(settings: settings, terminalSize: terminalSize)
    }
    
    // MARK: - Connect (Interactive / YubiKey)
    
    public func connectInteractive(
        host: String,
        port: Int = 22,
        username: String,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let delegate = KeyboardInteractiveDelegate(username: username)
        delegate.onOutput = self.onOutput
        let settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .custom(delegate) },
            hostKeyValidator: .acceptAnything()
        )
        await startSession(settings: settings, terminalSize: terminalSize)
    }
    
    public func log(_ msg: String, color: String = "36") {
        let text = "\r\n\u{1B}[\(color)m\(msg)\u{1B}[0m\r\n"
        let data = Data(text.utf8)
        if let onOutput = onOutput {
            onOutput(data)
        } else {
            logBuffer.append(data)
        }
    }
    
    // MARK: - Internal Session
    
    private func startSession(
        settings: SSHClientSettings,
        terminalSize: (cols: Int, rows: Int)
    ) async {
        await MainActor.run { connectionState = .connecting }
        
        // Create stdin stream
        let (stdinStream, stdinContinuation) = AsyncStream<Data>.makeStream()
        self.stdinContinuation = stdinContinuation
        
        sessionTask = Task { [weak self] in
            guard let self else { return }
            do {
                await MainActor.run { self.log("Connecting to \(settings.host):\(settings.port)...") }
                let sshClient = try await SSHClient.connect(to: settings)
                await MainActor.run { 
                    self.client = sshClient
                    self.log("TCP Connected & Authenticated.", color: "32")
                }
                
                await MainActor.run { self.currentTerminalSize = terminalSize }
                
                // Open an interactive shell session using PTY
                let ptyRequest = SSHChannelRequestEvent.PseudoTerminalRequest(
                    wantReply: true,
                    term: "xterm-256color",
                    terminalCharacterWidth: terminalSize.cols,
                    terminalRowHeight: terminalSize.rows,
                    terminalPixelWidth: 0,
                    terminalPixelHeight: 0,
                    terminalModes: .init([:])
                )
                
                
                try await sshClient.withPTY(ptyRequest) { inbound, outbound in
                    await MainActor.run { 
                        self.log("PTY Granted. Starting Shell...", color: "32")
                        self.stdinWriter = outbound
                        self.connectionState = .connected 
                    }
                    
                    // Handle Stdin
                    let stdinTask = Task {
                        for await data in stdinStream {
                            let buffer = ByteBuffer(data: data)
                            try await outbound.write(buffer)
                        }
                    }
                    
                    // Handle Output
                    var chunkCount = 0
                    for try await output in inbound {
                        chunkCount += 1
                        switch output {
                        case .stdout(let buffer):
                            let data = Data(buffer.readableBytesView)
                            await MainActor.run { self.onOutput?(data) }
                        case .stderr(let buffer):
                            let data = Data(buffer.readableBytesView)
                            await MainActor.run { self.onOutput?(data) }
                        }
                    }
                    
                    
                    stdinTask.cancel()
                    
                    await MainActor.run {
                        self.stdinWriter = nil
                        self.connectionState = .disconnected
                        self.onDisconnect?()
                    }
                }
                
                
            } catch {
                await MainActor.run {
                    let errorMsg = "ERROR: \(error.localizedDescription)"
                    self.log(errorMsg, color: "31")
                    self.connectionState = .failed(error.localizedDescription)
                    self.onDisconnect?()
                }
            }
        }
    }
    
    // MARK: - Send Input
    
    /// Send keystrokes from the terminal view to the SSH session.
    public func send(_ data: Data) {
        stdinContinuation?.yield(data)
        
        // Also write directly to the SSH client channel if available
        guard let client = client else { return }
        var buffer = ByteBuffer()
        buffer.writeBytes(data)
        let channelData = SSHChannelData(type: .channel, data: .byteBuffer(buffer))
        _ = channelData // Will be used via channel write in a future iteration
        _ = client
    }
    
    /// Notify the SSH server of a terminal resize.
    public func resize(cols: Int, rows: Int) {
        currentTerminalSize = (cols, rows)
        
        guard let writer = stdinWriter else { return }
        Task {
            try? await writer.changeSize(cols: cols, rows: rows, pixelWidth: 0, pixelHeight: 0)
        }
    }
    
    // MARK: - Disconnect
    
    public func disconnect() {
        stdinContinuation?.finish()
        stdinContinuation = nil
        sessionTask?.cancel()
        sessionTask = nil
        client = nil
        connectionState = .disconnected
        onDisconnect?()
    }
    
    deinit {
        sessionTask?.cancel()
    }
}

// MARK: - Keyboard Interactive Auth Delegate

/// Handles keyboard-interactive SSH authentication (MFA, YubiKey prompts).
final class KeyboardInteractiveDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    let username: String
    
    init(username: String) {
        self.username = username
    }
    
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if availableMethods.contains(.password) || availableMethods.contains(.publicKey) {
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(
                username: username,
                serviceName: "ssh-connection",
                offer: .none
            ))
        } else {
            nextChallengePromise.fail(CitadelError.unsupported)
        }
    }
    
    private func log(_ msg: String) {
        let text = "\r\n\u{1B}[35m\(msg)\u{1B}[0m\r\n"
        onOutput?(Data(text.utf8))
    }
    
    var onOutput: ((Data) -> Void)?
}

