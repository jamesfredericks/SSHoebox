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
        let (validator, capturer) = buildValidator(for: host, port: port)
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .passwordBased(username: username, password: password) },
            hostKeyValidator: validator
        )
        settings.algorithms = .all
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
        let (validator, capturer) = buildValidator(for: host, port: port)
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .ed25519(username: username, privateKey: ed25519Key) },
            hostKeyValidator: validator
        )
        settings.algorithms = .all
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
        let (validator, capturer) = buildValidator(for: host, port: port)
        let delegate = KeyboardInteractiveDelegate(username: username)
        delegate.onOutput = self.onOutput
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .custom(delegate) },
            hostKeyValidator: validator
        )
        settings.algorithms = .all
        await startSession(settings: settings, terminalSize: terminalSize, capturer: capturer)
    }

    // MARK: - Host Key Validation (TOFU)

    /// Builds an `SSHHostKeyValidator` for the given host.
    ///
    /// - If a known host record exists in the repository, returns `.trustedKeys` using
    ///   the stored key. The connection will fail with `InvalidHostKey` if the server
    ///   presents a different key.
    /// - If no record exists, returns a `CapturingHostKeyValidator` that trusts the
    ///   first-seen key. The caller is responsible for persisting the captured key after
    ///   the connection succeeds (see `startSession`).
    private func buildValidator(
        for host: String,
        port: Int
    ) -> (SSHHostKeyValidator, CapturingHostKeyValidator?) {
        guard let repo = knownHostRepository else {
            return (.acceptAnything(), nil)
        }
        if let knownHost = try? repo.find(hostname: host, port: port),
           let storedKey = try? NIOSSHPublicKey(openSSHPublicKey: knownHost.openSSHPublicKey) {
            return (.trustedKeys([storedKey]), nil)
        }
        let capturer = CapturingHostKeyValidator()
        return (.custom(capturer), capturer)
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
        await MainActor.run { connectionState = .connecting }

        // Snapshot repo reference for use inside the Task (avoids actor isolation issues)
        let repoSnapshot = knownHostRepository

        // Create stdin stream
        let (stdinStream, stdinContinuation) = AsyncStream<Data>.makeStream()
        self.stdinContinuation = stdinContinuation

        sessionTask = Task { [weak self] in
            guard let self else { return }
            do {
                await MainActor.run { self.log("Connecting to \(settings.host):\(settings.port)...") }
                let sshClient = try await SSHClient.connect(to: settings)

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
                    try? repo.save(knownHost)
                    await MainActor.run {
                        self.log("New host key stored (Trust On First Use).", color: "32")
                        self.log("  Type:        \(keyType)", color: "32")
                        self.log("  Fingerprint: \(fingerprint)", color: "32")
                    }
                }
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
                        self.onConnected?()
                    }

                    // Sync the actual terminal size with the server immediately after the PTY is
                    // granted. sizeChanged fires before the connection is established, so the
                    // initial resize call is silently dropped (stdinWriter was nil at that point).
                    // Re-sending now keeps the server in sync with the view's real dimensions.
                    let actualSize = await MainActor.run { self.currentTerminalSize }
                    if actualSize.cols != terminalSize.cols || actualSize.rows != terminalSize.rows {
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
                
                
            } catch is InvalidHostKey {
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

