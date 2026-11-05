import Foundation
import Citadel
import Crypto
import NIOSSH
import NIOCore
import NIOPosix

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
    /// Diagnostic log of the current (or last) login attempt.
    private var trace: LoginTrace?

    /// The id of the latest login attempt, for finding it in the Login Log.
    @Published public private(set) var lastLoginAttemptID: String?

    private func newTrace() -> LoginTrace {
        let trace = LoginTrace()
        lastLoginAttemptID = trace.id
        return trace
    }
    
    // Stdin pipe: we write to this continuation to send data to the SSH channel
    private var stdinContinuation: AsyncStream<Data>.Continuation?
    
    // We need to keep a reference to the channel handler or channel to write stdin
    private var stdinWriter: TTYStdinWriter?
    private var logBuffer: [Data] = []
    /// The latest size reported by the terminal view, or nil before the first report. The view
    /// usually reports its size while the connection is still being set up.
    private var reportedTerminalSize: (cols: Int, rows: Int)?

    // A keyboard-interactive prompt waiting for the user's answer. While one is open, keystrokes
    // go to it rather than to the shell, which doesn't exist until login completes.
    private var promptReader: TerminalLineReader?
    private var promptContinuation: CheckedContinuation<String?, Never>?
    
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

    /// Logs in with `password`, by password auth or, when the server only takes keyboard-interactive
    /// (PAM, often followed by a one-time code), by answering its password prompt. Any other
    /// prompt is put to the user in the terminal.
    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        password: String,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let trace = newTrace()
        trace.begin("SSH", host: host, port: port, username: username,
                    method: "stored password (password auth, else keyboard-interactive)")
        guard let (validator, capturer) = buildValidator(for: host, port: port, trace: trace) else { return }
        await startSession(trace: trace, terminalSize: terminalSize, capturer: capturer) { generation in
            self.interactiveSettings(host: host, port: port, username: username, password: password,
                                     validator: validator, generation: generation, trace: trace)
        }
    }

    // MARK: - Connect (Ed25519 Key)

    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        ed25519Key: Curve25519.Signing.PrivateKey,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let trace = newTrace()
        trace.begin("SSH", host: host, port: port, username: username, method: "publickey")
        await connectEd25519(host: host, port: port, username: username, ed25519Key: ed25519Key,
                             terminalSize: terminalSize, trace: trace)
    }

    private func connectEd25519(
        host: String,
        port: Int,
        username: String,
        ed25519Key: Curve25519.Signing.PrivateKey,
        terminalSize: (cols: Int, rows: Int),
        trace: LoginTrace
    ) async {
        let fingerprint = sshFingerprint(for: NIOSSHPrivateKey(ed25519Key: ed25519Key).publicKey)
        trace.info("key: ssh-ed25519 \(fingerprint); the server must list it in authorized_keys")
        guard let (validator, capturer) = buildValidator(for: host, port: port, trace: trace) else { return }
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .ed25519(username: username, privateKey: ed25519Key) },
            hostKeyValidator: validator
        )
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        await startSession(trace: trace, terminalSize: terminalSize, capturer: capturer) { _ in settings }
    }

    private func connectRSA(
        host: String,
        port: Int,
        username: String,
        rsaKey: RSALoginKey,
        terminalSize: (cols: Int, rows: Int),
        trace: LoginTrace
    ) async {
        trace.info("key: ssh-rsa \(rsaKey.bits)-bit \(rsaKey.format.rawValue) key \(sshFingerprint(forBlob: rsaKey.publicKeyBlob)); "
                   + "logs in as \(RSALoginKey.algorithms.joined(separator: ", then ")) (never SHA-1 ssh-rsa); "
                   + "the server must list it in authorized_keys")
        guard let (validator, capturer) = buildValidator(for: host, port: port, trace: trace) else { return }
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: {
                .custom(PublicKeyAuthenticator(username: username, attempts: rsaKey.loginAttempts, trace: trace))
            },
            hostKeyValidator: validator
        )
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        await startSession(trace: trace, terminalSize: terminalSize, capturer: capturer) { _ in settings }
    }

    // MARK: - Connect (PEM Key — Ed25519 or RSA, falls back to interactive)

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
        let trace = newTrace()
        trace.begin("SSH", host: host, port: port, username: username,
                    method: "stored private key" + (passphrase == nil ? "" : " with a passphrase from the user"))
        // The armor line names the format (OPENSSH, RSA, EC, ...) and isn't secret.
        let armor = pemKey.split(whereSeparator: \.isNewline).first.map(String.init) ?? "(empty)"
        trace.info("key: format \(LoginTrace.quoted(armor))")

        if let ed25519Key = try? Curve25519.Signing.PrivateKey(sshEd25519: pemKey, decryptionKey: decryptionKey) {
            passphraseChallenge = nil
            await connectEd25519(host: host, port: port, username: username, ed25519Key: ed25519Key,
                                 terminalSize: terminalSize, trace: trace)
            return
        }

        do {
            if let rsaKey = try RSALoginKey.parse(pem: pemKey, decryptionKey: decryptionKey) {
                passphraseChallenge = nil
                await connectRSA(host: host, port: port, username: username, rsaKey: rsaKey,
                                 terminalSize: terminalSize, trace: trace)
                return
            }
        } catch {
            trace.error("key: \(LoginTrace.describe(error))")
            log("⚠  \(error.localizedDescription)", color: "31")
            connectionState = .failed(error.localizedDescription)
            return
        }

        // Key is encrypted and no (or wrong) passphrase was provided
        if SSHKeyParser.isEncryptedKey(pemKey) {
            if passphrase == nil {
                trace.info("key: encrypted; asking the user for its passphrase (a new attempt follows)")
                passphraseChallenge = SSHPassphraseChallenge(
                    pemKey: pemKey, host: host, port: port,
                    username: username, terminalSize: terminalSize
                )
            } else {
                trace.error("key: passphrase is incorrect, or the key isn't an Ed25519 or RSA key")
                log("Incorrect passphrase for private key.", color: "31")
                connectionState = .failed("Incorrect key passphrase — please try again.")
            }
            return
        }

        let fingerprint = (try? SSHKeyParser.publicKeyBlob(fromPEM: pemKey)).map(sshFingerprint(forBlob:))
        trace.error("key: not an Ed25519 or RSA key\(fingerprint.map { " (\($0))" } ?? ""); only those are "
                    + "supported for direct login, so the key is NOT used and keyboard-interactive is tried instead")
        log("Key type not supported for direct auth — using keyboard-interactive.", color: "33")
        await connectInteractive(host: host, port: port, username: username, terminalSize: terminalSize, trace: trace)
    }

    // MARK: - Connect (External SSH Agent)

    /// Logs in with a key held by an external agent (Bitwarden, 1Password, ...). The agent signs
    /// the login, and may first ask the user to approve it in the password manager.
    public func connect(
        host: String,
        port: Int = 22,
        username: String,
        agentKey: SSHAgentKeyReference,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let trace = newTrace()
        trace.begin("SSH", host: host, port: port, username: username, method: "publickey from an external SSH agent")
        trace.info("key: \(agentKey.algorithm ?? "unknown type") \(agentKey.fingerprint) "
                   + "\(LoginTrace.quoted(agentKey.comment)) via agent socket \(agentKey.socketPath)")
        // The check below waits on the agent; a disconnect meanwhile cancels this connect.
        let startGeneration = generation
        let privateKey: NIOSSHPrivateKey
        do {
            privateKey = try await AgentBackedKey.checkedPrivateKey(for: agentKey)
            guard generation == startGeneration else {
                trace.info("cancelled while checking the agent")
                return
            }
            trace.info("agent: reachable and still holds the key")
        } catch {
            guard generation == startGeneration else { return }
            trace.error("agent: check failed: \(LoginTrace.describe(error))")
            log("⚠  \(error.localizedDescription)", color: "31")
            connectionState = .failed(error.localizedDescription)
            onDisconnect?()
            return
        }
        guard let (validator, capturer) = buildValidator(for: host, port: port, trace: trace) else { return }

        // Signing blocks the event loop while the agent waits for approval, so this connection
        // gets a loop of its own rather than stalling every other session on the shared one.
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: {
                .custom(AgentKeyAuthenticator(username: username, privateKey: privateKey, trace: trace))
            },
            hostKeyValidator: validator
        )
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        settings.group = group
        settings.loginTimeout = AgentBackedKey.loginTimeout
        let keyName = agentKey.comment.isEmpty ? agentKey.fingerprint : agentKey.comment
        log("Using \(keyName) from the SSH agent. Approve the request if your password manager asks.")
        await startSession(trace: trace, terminalSize: terminalSize, capturer: capturer, ownedGroup: group) { _ in settings }
    }

    // MARK: - Connect (Interactive / YubiKey)

    /// Logs in by keyboard-interactive with nothing stored: every prompt (password, one-time
    /// code, YubiKey) is answered by the user in the terminal.
    public func connectInteractive(
        host: String,
        port: Int = 22,
        username: String,
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        let trace = newTrace()
        trace.begin("SSH", host: host, port: port, username: username,
                    method: "keyboard-interactive (no stored credential; the user answers every prompt)")
        await connectInteractive(host: host, port: port, username: username, terminalSize: terminalSize, trace: trace)
    }

    private func connectInteractive(
        host: String,
        port: Int,
        username: String,
        terminalSize: (cols: Int, rows: Int),
        trace: LoginTrace
    ) async {
        guard let (validator, capturer) = buildValidator(for: host, port: port, trace: trace) else { return }
        await startSession(trace: trace, terminalSize: terminalSize, capturer: capturer) { generation in
            self.interactiveSettings(host: host, port: port, username: username, password: nil,
                                     validator: validator, generation: generation, trace: trace)
        }
    }

    private func interactiveSettings(
        host: String,
        port: Int,
        username: String,
        password: String?,
        validator: SSHHostKeyValidator,
        generation: Int,
        trace: LoginTrace
    ) -> SSHClientSettings {
        let ask: KeyboardInteractiveAuthenticator.Ask = { [weak self] prompt, echo in
            guard let self else { return nil }
            return await self.promptUser(prompt, echo: echo, generation: generation)
        }
        let show: KeyboardInteractiveAuthenticator.Show = { [weak self] text in
            await self?.showPromptText(text, generation: generation)
        }
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: {
                .custom(KeyboardInteractiveAuthenticator(username: username, password: password,
                                                         ask: ask, show: show, trace: trace))
            },
            hostKeyValidator: validator
        )
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        // Leave time to type a one-time code; the server's own LoginGraceTime still applies.
        settings.loginTimeout = .seconds(180)
        return settings
    }

    // MARK: - Login Prompts

    /// Shows `prompt` in the terminal and waits for the user to type an answer and press Return.
    /// Returns nil if they cancel (Ctrl-C) or the session is torn down first.
    private func promptUser(_ prompt: String, echo: Bool, generation: Int) async -> String? {
        // A superseded connection mustn't prompt in its replacement's terminal.
        guard generation == self.generation else { return nil }
        cancelPrompt()
        showPromptText(prompt, generation: generation)
        return await withCheckedContinuation { continuation in
            promptReader = TerminalLineReader(echo: echo)
            promptContinuation = continuation
        }
    }

    private func showPromptText(_ text: String, generation: Int) {
        guard generation == self.generation else { return }
        let terminalText = text.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        emit(Data(terminalText.utf8))
    }

    private func cancelPrompt() {
        let continuation = promptContinuation
        promptReader = nil
        promptContinuation = nil
        continuation?.resume(returning: nil)
    }

    // MARK: - Host Key Validation (TOFU)

    /// Builds the host key validator for `host:port` (see `HostKeyTrust.validator`).
    /// Returns nil, after reporting the reason and marking the session failed, when the
    /// trust state can't be determined; the caller must not connect in that case.
    private func buildValidator(
        for host: String,
        port: Int,
        trace: LoginTrace
    ) -> (SSHHostKeyValidator, CapturingHostKeyValidator?)? {
        do {
            return try HostKeyTrust.validator(for: host, port: port, repository: knownHostRepository, trace: trace)
        } catch {
            log("⚠  \(error.localizedDescription)", color: "31")
            connectionState = .failed(error.localizedDescription)
            onDisconnect?()
            return nil
        }
    }
    
    public func log(_ msg: String, color: String = "36") {
        let text = "\r\n\u{1B}[\(color)m\(msg)\u{1B}[0m\r\n"
        emit(Data(text.utf8))
    }

    private func emit(_ data: Data) {
        if let onOutput = onOutput {
            onOutput(data)
        } else {
            logBuffer.append(data)
        }
    }
    
    // MARK: - Internal Session
    
    /// `makeSettings` gets the new session's generation, so anything the settings call back into
    /// (login prompts) can tell whether its session is still the current one.
    private func startSession(
        trace: LoginTrace,
        terminalSize: (cols: Int, rows: Int),
        capturer: CapturingHostKeyValidator? = nil,
        ownedGroup: EventLoopGroup? = nil,
        makeSettings: (_ generation: Int) -> SSHClientSettings
    ) async {
        // A reconnect replaces any previous session, so close its connection first.
        tearDown()
        generation += 1
        let gen = generation
        self.trace = trace
        var settings = makeSettings(gen)
        settings.debugObserver = trace.protocolObserver
        connectionState = .connecting
        trace.info("tcp: connecting to \(settings.host):\(settings.port), "
                   + "login timeout \(settings.loginTimeout.nanoseconds / 1_000_000_000)s")

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
                    trace.info("authenticated, but superseded by a disconnect or newer attempt; closing")
                    try? await sshClient.close()
                    return
                }
                self.client = sshClient
                trace.info("auth: SUCCESS, logged in")

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
                        trace.info("host key: stored \(keyType) \(fingerprint) as trusted (first use)")
                    } catch {
                        saveError = error
                        trace.error("host key: could not store \(keyType) \(fingerprint): \(LoginTrace.describe(error))")
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

                trace.info("pty: requesting xterm-256color \(requestedSize.cols)x\(requestedSize.rows)")
                try await sshClient.withPTY(ptyRequest) { inbound, outbound in
                    guard await MainActor.run(body: { self.generation == gen }) else { return }
                    trace.info("pty: pty-req and shell sent; login complete (a refusal shows as SSH_MSG_CHANNEL_FAILURE)")
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
                trace.info("session ended: the remote shell exited")
                self.trace = nil
                self.client = nil
                self.stdinWriter = nil
                self.connectionState = .disconnected
                self.onDisconnect?()
            } catch is InvalidHostKey {
                try? await openedClient?.close()
                guard self.generation == gen else { return }
                trace.error("failed: host key mismatch (see the presented and trusted fingerprints above)")
                self.trace = nil
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
                guard self.generation == gen else {
                    trace.info("ended by a disconnect or newer attempt (\(LoginTrace.describe(error)))")
                    return
                }
                trace.error("failed: \(LoginTrace.describe(error))")
                self.trace = nil
                // Login failed or timed out while a prompt was open: close it.
                self.cancelPrompt()
                self.client = nil
                self.stdinWriter = nil
                await MainActor.run {
                    let detailedError = (error as? SSHAgentClientError)?.localizedDescription
                        ?? String(describing: error)
                    let errorType = String(describing: type(of: error))
                    self.log("ERROR [\(errorType)]: \(detailedError)", color: "31")
                    self.connectionState = .failed(detailedError)
                    self.onDisconnect?()
                }
            }
        }

        // A connection with its own event loop shuts that loop down once its session is over.
        if let ownedGroup, let sessionTask {
            Task.detached {
                await sessionTask.value
                try? await ownedGroup.shutdownGracefully()
            }
        }
    }
    
    // MARK: - Send Input
    
    /// Send keystrokes from the terminal view to the SSH session.
    public func send(_ data: Data) {
        guard var reader = promptReader else {
            stdinContinuation?.yield(data)
            return
        }
        let (output, event) = reader.feed(data)
        if !output.isEmpty { emit(output) }
        switch event {
        case .pending:
            promptReader = reader
        case .submitted(let line):
            let continuation = promptContinuation
            promptReader = nil
            promptContinuation = nil
            continuation?.resume(returning: line)
        case .cancelled:
            cancelPrompt()
        }
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
        // `trace` is cleared once an attempt ends on its own, so this only logs a live one.
        trace?.info("disconnected by the user")
        trace = nil
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
        cancelPrompt()
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

// MARK: - Keyboard-Interactive Authenticator

public enum SSHLoginError: Error, CustomStringConvertible {
    /// The server accepts none of the methods this login can use.
    case noUsableMethod(String)
    /// The server rejected every attempt.
    case rejected
    /// The server rejected the stored key.
    case keyRejected
    /// The user cancelled a login prompt.
    case cancelled

    public var description: String {
        switch self {
        case .noUsableMethod(let methods):
            return "The server doesn't accept \(methods) login."
        case .rejected:
            return "The server rejected the login (wrong password or code?)."
        case .keyRejected:
            return "The server rejected the key. Is its public key in authorized_keys for this user?"
        case .cancelled:
            return "Login cancelled."
        }
    }
}

/// Password and keyboard-interactive login (RFC 4256). The stored password, if any, answers the
/// server's first password prompt; every other prompt, such as a one-time code or a YubiKey touch,
/// is put to the user. Like OpenSSH, it tries each method once and stops when they're used up,
/// rather than retrying a rejected secret.
///
/// NIOSSH calls the delegate methods on the connection's event loop, one at a time, which is
/// what guards the mutable state.
final class KeyboardInteractiveAuthenticator: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    /// Asks the user to answer `prompt`, showing what they type only when `echo` is true.
    /// Returns nil if they cancel.
    typealias Ask = @Sendable (_ prompt: String, _ echo: Bool) async -> String?
    /// Shows text from the server, or a note about an answer filled in automatically.
    typealias Show = @Sendable (_ text: String) async -> Void

    private let username: String
    private let password: String?
    private let ask: Ask
    private let show: Show
    private let trace: LoginTrace

    private var probed = false
    private var triedPassword = false
    private var triedKeyboardInteractive = false
    /// Set once the stored password has been sent, so a rejected one is never sent again.
    private var passwordSpent = false

    init(username: String, password: String?, ask: @escaping Ask, show: @escaping Show,
         trace: LoginTrace = LoginTrace()) {
        self.username = username
        self.password = password
        self.ask = ask
        self.show = show
        self.trace = trace
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        func offer(_ offer: NIOSSHUserAuthenticationOffer.Offer) {
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(
                username: username, serviceName: "ssh-connection", offer: offer))
        }

        // The first round comes before the server has said what it accepts. A `none` request
        // gets that list without spending one of the server's allowed attempts.
        guard probed else {
            probed = true
            trace.info("auth: sending 'none' to learn which methods the server accepts")
            offer(.none)
            return
        }

        let tried = [triedPassword ? "password" : nil, triedKeyboardInteractive ? "keyboard-interactive" : nil]
            .compactMap { $0 }
        trace.info("auth: server accepts [\(LoginTrace.describe(availableMethods))]"
                   + (tried.isEmpty ? "" : " after rejecting [\(tried.joined(separator: ", "))]"))

        if let password, !triedPassword, availableMethods.contains(.password) {
            triedPassword = true
            passwordSpent = true
            trace.info("auth: offering password (stored in vault)")
            offer(.password(.init(password: password)))
        } else if !triedKeyboardInteractive, availableMethods.contains(.keyboardInteractive) {
            triedKeyboardInteractive = true
            trace.info("auth: offering keyboard-interactive")
            offer(.keyboardInteractive(.init()))
        } else if triedPassword || triedKeyboardInteractive {
            trace.error("auth: no methods left to try; the server rejected [\(tried.joined(separator: ", "))]")
            nextChallengePromise.fail(SSHLoginError.rejected)
        } else {
            let wanted = password == nil ? "keyboard-interactive" : "password or keyboard-interactive"
            trace.error("auth: server accepts none of the methods this login can use (\(wanted))")
            nextChallengePromise.fail(SSHLoginError.noUsableMethod(wanted))
        }
    }

    func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        enum Answer {
            case stored(prompt: String, password: String)
            case ask(prompt: String, echo: Bool)
        }

        // Decide which prompts the stored password answers here, on the event loop.
        let answers: [Answer] = challenge.prompts.map { prompt in
            if let password, !passwordSpent, !prompt.echo, Self.isPasswordPrompt(prompt.prompt) {
                passwordSpent = true
                return .stored(prompt: prompt.prompt, password: password)
            }
            return .ask(prompt: prompt.prompt, echo: prompt.echo)
        }
        let header = [challenge.name, challenge.instruction].filter { !$0.isEmpty }
        let ask = self.ask
        let show = self.show
        let trace = self.trace

        trace.info("auth: keyboard-interactive challenge, name \(LoginTrace.quoted(challenge.name)), "
                   + "instruction \(LoginTrace.quoted(challenge.instruction)), \(challenge.prompts.count) prompt(s)")
        for (index, answer) in answers.enumerated() {
            switch answer {
            case .stored(let prompt, _):
                trace.info("auth:   prompt \(index + 1) \(LoginTrace.quoted(prompt)) (hidden): answered with the vault password")
            case .ask(let prompt, let echo):
                trace.info("auth:   prompt \(index + 1) \(LoginTrace.quoted(prompt)) (\(echo ? "echoed" : "hidden")): asking the user")
            }
        }

        Task {
            for line in header {
                await show(line.hasSuffix("\n") ? line : line + "\n")
            }
            var responses: [String] = []
            for answer in answers {
                switch answer {
                case .stored(let prompt, let password):
                    await show("\(prompt)\u{1B}[2m(from vault)\u{1B}[0m\n")
                    responses.append(password)
                case .ask(let prompt, let echo):
                    guard let response = await ask(prompt, echo) else {
                        trace.error("auth: user cancelled the prompt \(LoginTrace.quoted(prompt))")
                        responsePromise.fail(SSHLoginError.cancelled)
                        return
                    }
                    responses.append(response)
                }
            }
            trace.info("auth: sending \(responses.count) answer(s)")
            responsePromise.succeed(responses)
        }
    }

    /// Whether a prompt asks for the account password, as PAM's "Password: " does, rather than
    /// a one-time code ("Verification code: ", "One-time password (OATH) for ...").
    static func isPasswordPrompt(_ prompt: String) -> Bool {
        let text = prompt.lowercased()
        guard text.contains("password") else { return false }
        let oneTimeMarkers = ["one-time", "one time", "otp", "oath", "token", "code", "passcode", "new password"]
        return !oneTimeMarkers.contains { text.contains($0) }
    }
}
