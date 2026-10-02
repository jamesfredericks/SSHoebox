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

    /// Called once when the session transitions to .connected.
    public var onConnected: (() -> Void)?
    
    private var client: SSHClient?
    private var sessionTask: Task<Void, Never>?
    /// Bumped whenever a session starts or is torn down. A session task compares it with the
    /// value it started with, so a superseded connection never updates this manager's state.
    private var generation = 0
    
    // Stdin pipe: we write to this continuation to send data to the SSH channel
    private var stdinContinuation: AsyncStream<Data>.Continuation?
    
    // We need to keep a reference to the channel handler or channel to write stdin
    private var stdinWriter: TTYStdinWriter?
    private var logBuffer: [Data] = []
    /// The latest size reported by the terminal view, or nil before the first report. The view
    /// usually reports its size while the connection is still being set up.
    private var reportedTerminalSize: (cols: Int, rows: Int)?
    
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
    
    /// Set before calling connect to enable TOFU host key validation.
    /// When nil the session falls back to accepting any key (legacy behaviour).
    public var knownHostRepository: KnownHostRepository?

    /// Set when a PEM key requires a passphrase. The UI observes this to show a prompt.
    @Published public var passphraseChallenge: SSHPassphraseChallenge? = nil

    public init() {}

    // MARK: - Connect (Password)

    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        password: String,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        guard let (validator, capturer) = buildValidator(for: host, port: port) else { return }
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .passwordBased(username: username, password: password) },
            hostKeyValidator: validator
        )
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        await startSession(settings: settings, terminalSize: terminalSize, capturer: capturer)
    }

    // MARK: - Connect (Ed25519 Key)

    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        ed25519Key: Curve25519.Signing.PrivateKey,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        guard let (validator, capturer) = buildValidator(for: host, port: port) else { return }
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .ed25519(username: username, privateKey: ed25519Key) },
            hostKeyValidator: validator
        )
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        await startSession(settings: settings, terminalSize: terminalSize, capturer: capturer)
    }

    // MARK: - Connect (PEM Key — parses Ed25519, falls back to interactive)

    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        pemKey: String,
        passphrase: String? = nil,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let pemKey = SSHKeyParser.normalizedPEM(pemKey)
        let decryptionKey = passphrase.flatMap { $0.data(using: .utf8) }

        if let ed25519Key = try? Curve25519.Signing.PrivateKey(sshEd25519: pemKey, decryptionKey: decryptionKey) {
            passphraseChallenge = nil
            await connect(host: host, port: port, username: username, ed25519Key: ed25519Key, terminalSize: terminalSize)
            return
        }

        // Key is encrypted and no (or wrong) passphrase was provided
        if SSHKeyParser.isEncryptedKey(pemKey) {
            if passphrase == nil {
                passphraseChallenge = SSHPassphraseChallenge(
                    pemKey: pemKey, host: host, port: port,
                    username: username, terminalSize: terminalSize
                )
            } else {
                log("Incorrect passphrase for private key.", color: "31")
                connectionState = .failed("Incorrect key passphrase — please try again.")
            }
            return
        }

        log("Key type not supported for direct auth — using keyboard-interactive.", color: "33")
        await connectInteractive(host: host, port: port, username: username, terminalSize: terminalSize)
    }

    // MARK: - Connect (Interactive / YubiKey)

    public func connectInteractive(
        host: String,
        port: Int = 22,
        username: String,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        guard let (validator, capturer) = buildValidator(for: host, port: port) else { return }
        let delegate = KeyboardInteractiveDelegate(username: username)
        delegate.onOutput = self.onOutput
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .custom(delegate) },
            hostKeyValidator: validator
        )
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        await startSession(settings: settings, terminalSize: terminalSize, capturer: capturer)
    }

    // MARK: - Host Key Validation (TOFU)

    /// Builds the host key validator for `host:port` (see `HostKeyTrust.validator`).
    /// Returns nil, after reporting the reason and marking the session failed, when the
    /// trust state can't be determined; the caller must not connect in that case.
    private func buildValidator(
        for host: String,
        port: Int
    ) -> (SSHHostKeyValidator, CapturingHostKeyValidator?)? {
        do {
            return try HostKeyTrust.validator(for: host, port: port, repository: knownHostRepository)
        } catch {
            log("⚠  \(error.localizedDescription)", color: "31")
            connectionState = .failed(error.localizedDescription)
            onDisconnect?()
            return nil
        }
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
        terminalSize: (cols: Int, rows: Int),
        capturer: CapturingHostKeyValidator? = nil
    ) async {
        // A reconnect replaces any previous session, so close its connection first.
        tearDown()
        generation += 1
        let gen = generation
        connectionState = .connecting

        // Snapshot repo reference for use inside the Task (avoids actor isolation issues)
        let repoSnapshot = knownHostRepository

        // Create stdin stream
        let (stdinStream, stdinContinuation) = AsyncStream<Data>.makeStream()
        self.stdinContinuation = stdinContinuation

        sessionTask = Task { [weak self] in
            guard let self else { return }
            var openedClient: SSHClient?
            do {
                await MainActor.run { self.log("Connecting to \(settings.host):\(settings.port)...") }
                let sshClient = try await SSHClient.connect(to: settings)
                openedClient = sshClient

                // Disconnected (or reconnected) while the handshake was in flight.
                guard self.generation == gen else {
                    try? await sshClient.close()
                    return
                }
                self.client = sshClient

                // If this was a first-time connection, persist the captured key and log the fingerprint.
                // validateHostKey fires before SSHClient.connect returns, so capturedKey is set here.
                if let capturedKey = capturer?.capturedKey, let repo = repoSnapshot {
                    let fingerprint = sshFingerprint(for: capturedKey)
                    let openSSHStr = String(openSSHPublicKey: capturedKey)
                    let keyType = String(openSSHStr.split(separator: " ").first ?? "unknown")
                    let knownHost = KnownHost(
                        hostname: settings.host,
                        port: settings.port,
                        keyType: keyType,
                        keyFingerprint: fingerprint,
                        openSSHPublicKey: openSSHStr
                    )
                    let saveError: Error?
                    do {
                        try repo.save(knownHost)
                        saveError = nil
                    } catch {
                        saveError = error
                    }
                    await MainActor.run {
                        if let saveError {
                            self.log("Warning: could not store the host key (\(saveError.localizedDescription)).", color: "33")
                            self.log("It was accepted for this session only and will be trusted on first use again.", color: "33")
                        } else {
                            self.log("New host key stored (Trust On First Use).", color: "32")
                        }
                        self.log("  Type:        \(keyType)", color: "32")
                        self.log("  Fingerprint: \(fingerprint)", color: "32")
                    }
                }
                await MainActor.run {
                    self.log("TCP Connected & Authenticated.", color: "32")
                }
                
                // Request the PTY at the size the view last reported, falling back to the caller's
                // size if the view hasn't laid out yet.
                let requestedSize = self.reportedTerminalSize ?? terminalSize
                let ptyRequest = SSHChannelRequestEvent.PseudoTerminalRequest(
                    wantReply: true,
                    term: "xterm-256color",
                    terminalCharacterWidth: requestedSize.cols,
                    terminalRowHeight: requestedSize.rows,
                    terminalPixelWidth: 0,
                    terminalPixelHeight: 0,
                    terminalModes: .init([:])
                )

                try await sshClient.withPTY(ptyRequest) { inbound, outbound in
                    guard await MainActor.run(body: { self.generation == gen }) else { return }
                    await MainActor.run {
                        self.log("PTY Granted. Starting Shell...", color: "32")
                        self.stdinWriter = outbound
                        self.connectionState = .connected
                        self.onConnected?()
                    }

                    // resize() only forwards sizes once stdinWriter is set, so a resize that arrived
                    // between the PTY request and now was recorded but not sent. Send it now.
                    if let actualSize = await MainActor.run(body: { self.reportedTerminalSize }),
                       actualSize.cols != requestedSize.cols || actualSize.rows != requestedSize.rows {
                        try? await outbound.changeSize(
                            cols: actualSize.cols,
                            rows: actualSize.rows,
                            pixelWidth: 0,
                            pixelHeight: 0
                        )
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
                            await MainActor.run { if self.generation == gen { self.onOutput?(data) } }
                        case .stderr(let buffer):
                            let data = Data(buffer.readableBytesView)
                            await MainActor.run { if self.generation == gen { self.onOutput?(data) } }
                        }
                    }
                    
                    
                    stdinTask.cancel()
                }

                // The remote shell exited: close the SSH connection, not just the channel.
                try? await sshClient.close()
                guard self.generation == gen else { return }
                self.client = nil
                self.stdinWriter = nil
                self.connectionState = .disconnected
                self.onDisconnect?()
            } catch is InvalidHostKey {
                try? await openedClient?.close()
                guard self.generation == gen else { return }
                self.client = nil
                await MainActor.run {
                    self.log("", color: "31")
                    self.log("⚠  WARNING: HOST KEY VERIFICATION FAILED", color: "31")
                    self.log("The server presented a key that does not match the trusted key on record.", color: "31")
                    self.log("This may indicate a man-in-the-middle attack or a server reinstall.", color: "33")
                    self.log("If you trust this change, remove the host from Preferences → Known Hosts,", color: "33")
                    self.log("then reconnect to store the new key.", color: "33")
                    self.log("", color: "31")
                    self.connectionState = .failed("Host key mismatch")
                    self.onDisconnect?()
                }
            } catch {
                try? await openedClient?.close()
                // A deliberate disconnect makes the in-flight session throw; that isn't a failure.
                guard self.generation == gen else { return }
                self.client = nil
                self.stdinWriter = nil
                await MainActor.run {
                    let detailedError = String(describing: error)
                    let errorType = String(describing: type(of: error))
                    self.log("ERROR [\(errorType)]: \(detailedError)", color: "31")
                    self.connectionState = .failed(detailedError)
                    self.onDisconnect?()
                }
            }
        }
    }
    
    // MARK: - Send Input
    
    /// Send keystrokes from the terminal view to the SSH session.
    public func send(_ data: Data) {
        stdinContinuation?.yield(data)
    }
    
    /// Notify the SSH server of a terminal resize.
    /// Guards against zero/negative values that crash Citadel's WindowChangeRequest.
    public func resize(cols: Int, rows: Int) {
        guard cols > 0, rows > 0 else { return }
        reportedTerminalSize = (cols, rows)
        
        guard let writer = stdinWriter else { return }
        Task {
            try? await writer.changeSize(cols: cols, rows: rows, pixelWidth: 0, pixelHeight: 0)
        }
    }
    
    // MARK: - Disconnect
    
    public func disconnect() {
        tearDown()
        passphraseChallenge = nil
        connectionState = .disconnected
        onDisconnect?()
    }

    /// Ends the current session, if any, and closes its SSH connection. Citadel's `SSHClient`
    /// doesn't close itself on release, so dropping the reference alone would leave the
    /// TCP connection (and the authenticated session) open.
    private func tearDown() {
        generation += 1
        stdinContinuation?.finish()
        stdinContinuation = nil
        stdinWriter = nil
        sessionTask?.cancel()
        sessionTask = nil
        if let client {
            Task { try? await client.close() }
        }
        client = nil
    }
    
    deinit {
        sessionTask?.cancel()
        if let client {
            Task { try? await client.close() }
        }
    }
}

// MARK: - Passphrase Challenge

/// Carries the context needed to retry a connection once the user supplies a passphrase.
public struct SSHPassphraseChallenge: Identifiable {
    public let id = UUID()
    public let pemKey: String
    public let host: String
    public let port: Int
    public let username: String
    public let terminalSize: (cols: Int, rows: Int)
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

