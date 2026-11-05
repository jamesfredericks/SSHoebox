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

    /// A port forward of this session and how it's doing.
    public struct ForwardStatus: Identifiable, Equatable {
        public enum State: Equatable {
            case stopped
            case listening
            case failed(String)
        }
        public let forward: PortForward
        public var state: State
        public var id: String { forward.id }
    }

    @Published public var connectionState: ConnectionState = .disconnected

    /// Called when the session ends (disconnect or error).
    public var onDisconnect: (() -> Void)?

    /// Called once when the session transitions to .connected.
    public var onConnected: (() -> Void)?

    /// The current connection (target plus any jump hosts), once logged in.
    private var route: SSHRoute?
    private var sessionTask: Task<Void, Never>?
    private var keepAliveTask: Task<Void, Never>?
    /// Bumped whenever a session starts or is torn down. A session task compares it with the
    /// value it started with, so a superseded connection never updates this manager's state.
    private var generation = 0
    /// Diagnostic log of the current (or last) login attempt.
    private var trace: LoginTrace?

    /// The id of the latest login attempt, for finding it in the Login Log.
    @Published public private(set) var lastLoginAttemptID: String?

    /// `user@host:port` of the latest target, and the jump hosts it goes through.
    @Published public private(set) var endpoint: String?
    @Published public private(set) var jumpEndpoints: [String] = []

    /// This session's port forwards: those of the host, running or not.
    @Published public private(set) var forwards: [ForwardStatus] = []
    private var forwarders: [String: LocalPortForwarder] = [:]

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

    // MARK: - Connect

    /// Logs in to `target`, through `jumps` in order if any (`ssh -J first,second`), and
    /// starts a shell. Each login uses its own credential; keyboard-interactive prompts from
    /// any of them are answered in the terminal.
    public func connect(
        _ target: SSHLogin,
        via jumps: [SSHLogin] = [],
        options: SSHSessionOptions = SSHSessionOptions(),
        terminalSize: (cols: Int, rows: Int) = (80, 24)
    ) async {
        // A reconnect replaces any previous session, so close its connection first.
        tearDown()
        let gen = generation
        passphraseChallenge = nil
        endpoint = target.endpoint
        jumpEndpoints = jumps.map(\.endpoint)
        forwards = options.portForwards.map { ForwardStatus(forward: $0, state: .stopped) }

        let trace = newTrace()
        self.trace = trace
        trace.begin("SSH", host: target.host, port: target.port, username: target.username,
                    method: target.auth.methodDescriptionForTrace)
        if !jumps.isEmpty {
            trace.info("route: through \(jumps.map(\.endpoint).joined(separator: ", then ")) (ssh -J)")
            for (index, jump) in jumps.enumerated() {
                trace.info("route: jump host \(index + 1) \(jump.endpoint) logs in with \(jump.auth.methodDescriptionForTrace)")
            }
        }
        connectionState = .connecting

        let prompter = LoginPrompter(
            ask: { [weak self] prompt, echo in
                guard let self else { return nil }
                return await self.promptUser(prompt, echo: echo, generation: gen)
            },
            show: { [weak self] text in
                await self?.showPromptText(text, generation: gen)
            }
        )
        let preparer = SSHLoginPreparer(repository: knownHostRepository, trace: trace, prompter: prompter)
        var prepared: [PreparedLogin] = []
        for (index, login) in (jumps + [target]).enumerated() {
            let isTarget = index == jumps.count
            if !isTarget { trace.info("route: preparing jump host \(index + 1) \(login.endpoint)") }
            else if !jumps.isEmpty { trace.info("route: preparing target \(login.endpoint)") }
            let outcome = await preparer.prepare(login)
            // Disconnected (or reconnected) while checking an agent.
            guard generation == gen else {
                trace.info("cancelled while preparing the login")
                return
            }
            switch outcome {
            case .ready(let step):
                prepared.append(step)
            case .needsPassphrase:
                self.trace = nil
                connectionState = .disconnected
                passphraseChallenge = SSHPassphraseChallenge(target: target, jumps: jumps,
                                                             jumpIndex: isTarget ? nil : index,
                                                             options: options, terminalSize: terminalSize)
                return
            case .failed(let message):
                self.trace = nil
                let prefix = isTarget ? "" : "Jump host \(login.endpoint): "
                log("⚠  \(prefix)\(message)", color: "31")
                connectionState = .failed(prefix + message)
                onDisconnect?()
                return
            }
        }
        startSession(prepared, generation: gen, trace: trace, terminalSize: terminalSize, options: options)
    }

    /// Connects again with the passphrase the user gave for the challenge's key.
    public func connect(answering challenge: SSHPassphraseChallenge, passphrase: String) async {
        let (target, jumps) = challenge.answered(with: passphrase)
        await connect(target, via: jumps, options: challenge.options, terminalSize: challenge.terminalSize)
    }

    /// Logs in with `password`, by password auth or, when the server only takes keyboard-interactive
    /// (PAM, often followed by a one-time code), by answering its password prompt. Any other
    /// prompt is put to the user in the terminal.
    public func connect(host: String, port: Int = 22, username: String, password: String,
                        terminalSize: (cols: Int, rows: Int) = (80, 24)) async {
        await connect(SSHLogin(host: host, port: port, username: username, auth: .password(password)),
                      terminalSize: terminalSize)
    }

    /// Logs in with a stored key (Ed25519, ECDSA or RSA). A key of another type falls back to
    /// keyboard-interactive; an encrypted key without `passphrase` raises `passphraseChallenge`.
    public func connect(host: String, port: Int = 22, username: String, pemKey: String, passphrase: String? = nil,
                        terminalSize: (cols: Int, rows: Int) = (80, 24)) async {
        await connect(SSHLogin(host: host, port: port, username: username,
                               auth: .privateKey(pem: pemKey, passphrase: passphrase)),
                      terminalSize: terminalSize)
    }

    /// Logs in with a key held by an external agent (Bitwarden, 1Password, ...). The agent signs
    /// the login, and may first ask the user to approve it in the password manager.
    public func connect(host: String, port: Int = 22, username: String, agentKey: SSHAgentKeyReference,
                        terminalSize: (cols: Int, rows: Int) = (80, 24)) async {
        await connect(SSHLogin(host: host, port: port, username: username, auth: .agentKey(agentKey)),
                      terminalSize: terminalSize)
    }

    /// Logs in by keyboard-interactive with nothing stored: every prompt (password, one-time
    /// code, YubiKey) is answered by the user in the terminal.
    public func connectInteractive(host: String, port: Int = 22, username: String,
                                   terminalSize: (cols: Int, rows: Int) = (80, 24)) async {
        await connect(SSHLogin(host: host, port: port, username: username, auth: .interactive),
                      terminalSize: terminalSize)
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

    private func startSession(
        _ prepared: [PreparedLogin],
        generation gen: Int,
        trace: LoginTrace,
        terminalSize: (cols: Int, rows: Int),
        options: SSHSessionOptions
    ) {
        let target = prepared[prepared.count - 1].login
        let jumps = prepared.dropLast().map(\.login)

        // Snapshot repo reference for use inside the Task (avoids actor isolation issues)
        let repoSnapshot = knownHostRepository

        // Create stdin stream
        let (stdinStream, stdinContinuation) = AsyncStream<Data>.makeStream()
        self.stdinContinuation = stdinContinuation

        sessionTask = Task { [weak self] in
            guard let self else { return }
            var openedRoute: SSHRoute?
            do {
                await MainActor.run {
                    for jump in jumps { self.log("Connecting through \(jump.endpoint)...") }
                    self.log("Connecting to \(target.host):\(target.port)...")
                }
                let route = try await SSHRoute.connect(prepared, repository: repoSnapshot, trace: trace)
                openedRoute = route

                // Disconnected (or reconnected) while the handshake was in flight.
                guard self.generation == gen else {
                    trace.info("authenticated, but superseded by a disconnect or newer attempt; closing")
                    await route.close()
                    return
                }
                self.route = route
                trace.info("auth: SUCCESS, logged in")

                await MainActor.run {
                    for key in route.storedHostKeys {
                        let whose = key.endpoint == target.endpoint ? "" : " for \(key.endpoint)"
                        if let saveError = key.saveError {
                            self.log("Warning: could not store the host key\(whose) (\(saveError)).", color: "33")
                            self.log("It was accepted for this session only and will be trusted on first use again.", color: "33")
                        } else {
                            self.log("New host key stored\(whose) (Trust On First Use).", color: "32")
                        }
                        self.log("  Type:        \(key.keyType)", color: "32")
                        self.log("  Fingerprint: \(key.fingerprint)", color: "32")
                    }
                    self.log("TCP Connected & Authenticated.", color: "32")
                }

                self.startKeepAlive(route: route, options: options, endpoint: target.endpoint, generation: gen, trace: trace)
                await self.startAutoForwards(route: route, generation: gen)

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
                try await route.client.withPTY(ptyRequest) { inbound, outbound in
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

                    // Typed as if by the user, so it runs in the login shell like anything else.
                    if let command = options.startupCommand?.trimmingCharacters(in: .whitespacesAndNewlines),
                       !command.isEmpty {
                        trace.info("shell: sending the host's startup command")
                        stdinContinuation.yield(Data((command + "\r").utf8))
                    }

                    // Handle Output
                    for try await output in inbound {
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
                await route.close()
                guard self.generation == gen else { return }
                trace.info("session ended: the remote shell exited")
                self.endSession()
                self.connectionState = .disconnected
                self.onDisconnect?()
            } catch is InvalidHostKey {
                await openedRoute?.close()
                guard self.generation == gen else { return }
                trace.error("failed: host key mismatch (see the presented and trusted fingerprints above)")
                self.endSession()
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
                await openedRoute?.close()
                // A deliberate disconnect makes the in-flight session throw; that isn't a failure.
                guard self.generation == gen else {
                    trace.info("ended by a disconnect or newer attempt (\(LoginTrace.describe(error)))")
                    return
                }
                trace.error("failed: \(LoginTrace.describe(error))")
                self.endSession()
                await MainActor.run {
                    let detailedError = (error as? SSHAgentClientError)?.localizedDescription
                        ?? ConnectionErrorText.describe(error)
                        ?? String(describing: error)
                    let errorType = String(describing: type(of: error))
                    self.log("ERROR [\(errorType)]: \(detailedError)", color: "31")
                    self.connectionState = .failed(detailedError)
                    self.onDisconnect?()
                }
            }
        }
    }

    /// Clears what a session that ended on its own leaves behind.
    private func endSession() {
        trace = nil
        // Login failed or timed out while a prompt was open: close it.
        cancelPrompt()
        route = nil
        stdinWriter = nil
        stopForwarders()
        keepAliveTask?.cancel()
        keepAliveTask = nil
    }

    // MARK: - Keep-Alive

    private func startKeepAlive(route: SSHRoute, options: SSHSessionOptions, endpoint: String,
                                generation gen: Int, trace: LoginTrace) {
        guard options.keepAliveInterval > 0 else {
            trace.info("keep-alive: off for this host")
            return
        }
        trace.info("keep-alive: every \(options.keepAliveInterval)s; the connection is closed after "
                   + "\(options.keepAliveCountMax) unanswered in a row")
        keepAliveTask = SSHKeepAlive.start(route: route, interval: options.keepAliveInterval,
                                           countMax: options.keepAliveCountMax, endpoint: endpoint) { [weak self] in
            await MainActor.run {
                guard let self, self.generation == gen else { return }
                self.log("The server stopped answering keep-alives; the connection is closed.", color: "31")
            }
            await route.close()
        }
    }

    // MARK: - Port Forwards

    private func startAutoForwards(route: SSHRoute, generation gen: Int) async {
        for status in forwards where status.forward.autoStart {
            await startForward(status.forward, route: route, generation: gen)
        }
    }

    /// Starts one of this session's port forwards over the current connection.
    public func startForward(id: String) async {
        guard let route, let status = forwards.first(where: { $0.id == id }) else { return }
        await startForward(status.forward, route: route, generation: generation)
    }

    private func startForward(_ forward: PortForward, route: SSHRoute, generation gen: Int) async {
        guard forwarders[forward.id] == nil else { return }
        do {
            let forwarder = try await LocalPortForwarder.start(forward, over: route.client) { message in
                LoginTrace.event(message, level: .error)
            }
            guard generation == gen else {
                forwarder.stop()
                return
            }
            forwarders[forward.id] = forwarder
            setForwardState(forward.id, .listening)
            LoginTrace.event("tunnel: listening on \(forward.bindAddress):\(forward.localPort) → "
                             + "\(forward.remoteHost):\(forward.remotePort) via \(endpoint ?? "the server")")
            log("Tunnel open: \(forward.summary)", color: "32")
        } catch {
            guard generation == gen else { return }
            let reason = Self.describeBindError(error, port: forward.localPort)
            setForwardState(forward.id, .failed(reason))
            LoginTrace.event("tunnel \(forward.summary): \(reason)", level: .error)
            log("Tunnel \(forward.summary) not opened: \(reason)", color: "33")
        }
    }

    /// Stops one of this session's port forwards.
    public func stopForward(id: String) {
        forwarders.removeValue(forKey: id)?.stop()
        setForwardState(id, .stopped)
    }

    private func stopForwarders() {
        for forwarder in forwarders.values { forwarder.stop() }
        forwarders.removeAll()
        for index in forwards.indices { forwards[index].state = .stopped }
    }

    private func setForwardState(_ id: String, _ state: ForwardStatus.State) {
        guard let index = forwards.firstIndex(where: { $0.id == id }) else { return }
        forwards[index].state = state
    }

    static func describeBindError(_ error: Error, port: Int) -> String {
        if let io = error as? IOError {
            switch io.errnoCode {
            case EADDRINUSE: return "port \(port) is already in use (another tab or app?)"
            case EACCES: return "port \(port) needs administrator rights (use 1024 or above)"
            default: break
            }
        }
        return LoginTrace.describe(error)
    }

    // MARK: - Remote Commands

    /// Runs `command` on the target over a separate channel of this session (not in the
    /// shell) and returns its output. Throws if it exits non-zero.
    public func run(_ command: String) async throws -> String {
        guard let route else { throw SFTPManagerError.notConnected }
        let output = try await route.client.executeCommand(command)
        return String(buffer: output)
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
        keepAliveTask?.cancel()
        keepAliveTask = nil
        stopForwarders()
        if let route {
            Task { await route.close() }
        }
        route = nil
    }

    deinit {
        sessionTask?.cancel()
        keepAliveTask?.cancel()
        for forwarder in forwarders.values { forwarder.stop() }
        if let route {
            Task { await route.close() }
        }
    }
}

extension SSHLogin.Auth {
    var methodDescriptionForTrace: String {
        SSHLogin(host: "", username: "", auth: self).methodDescription
    }
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
