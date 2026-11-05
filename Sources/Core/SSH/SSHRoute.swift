import Foundation
import Citadel
import Crypto
import NIOCore
import NIOPosix
import NIOSSH

// MARK: - What to log in to

/// One SSH login: where, as whom, and with what. A session is a target login, optionally
/// reached through jump hosts (`ssh -J`), each a login of its own.
public struct SSHLogin: Sendable {
    public enum Auth: Sendable {
        /// A stored password: password auth, else keyboard-interactive answering the password
        /// prompt (any other prompt goes to the user, where there's a terminal to ask in).
        case password(String)
        /// A stored private key (Ed25519, ECDSA or RSA; OpenSSH, PKCS#1, SEC1 or PKCS#8).
        case privateKey(pem: String, passphrase: String?)
        /// A key held by an external agent, which may ask the user to approve each login.
        case agentKey(SSHAgentKeyReference)
        /// Nothing stored: keyboard-interactive, with every prompt put to the user.
        case interactive
    }

    public var host: String
    public var port: Int
    public var username: String
    public var auth: Auth

    public init(host: String, port: Int = 22, username: String, auth: Auth) {
        self.host = host
        self.port = port
        self.username = username
        self.auth = auth
    }

    /// `user@host:port`, for logs and messages.
    public var endpoint: String { "\(username)@\(host):\(port)" }

    /// The login method as the login log describes it. Never includes the secret.
    var methodDescription: String {
        switch auth {
        case .password: return "stored password (password auth, else keyboard-interactive)"
        case .privateKey(_, let passphrase):
            return "stored private key" + (passphrase == nil ? "" : " with a passphrase from the user")
        case .agentKey: return "publickey from an external SSH agent"
        case .interactive: return "keyboard-interactive (no stored credential; the user answers every prompt)"
        }
    }

    /// This login with `passphrase` for its key, if it uses a stored key.
    func withPassphrase(_ passphrase: String) -> SSHLogin {
        guard case .privateKey(let pem, _) = auth else { return self }
        var login = self
        login.auth = .privateKey(pem: pem, passphrase: passphrase)
        return login
    }
}

/// Connection settings that apply to the whole session rather than one login.
public struct SSHSessionOptions: Sendable, Equatable {
    /// Seconds between keep-alives; 0 turns them off.
    public var keepAliveInterval: Int
    /// Missed keep-alives in a row before the connection is treated as dead
    /// (OpenSSH's `ServerAliveCountMax`).
    public var keepAliveCountMax: Int
    /// Local port forwards to open once the session connects (those marked auto-start).
    public var portForwards: [PortForward]
    /// Typed into the shell once it starts (terminal sessions only).
    public var startupCommand: String?

    public static let defaultKeepAliveInterval = 30
    public static let keepAliveDefaultsKey = "keepAliveInterval"

    /// The keep-alive interval set in Preferences, or 30 seconds.
    public static var preferredKeepAliveInterval: Int {
        let value = UserDefaults.standard.object(forKey: keepAliveDefaultsKey) as? Int
        return value ?? defaultKeepAliveInterval
    }

    public init(keepAliveInterval: Int = SSHSessionOptions.preferredKeepAliveInterval,
                keepAliveCountMax: Int = 3,
                portForwards: [PortForward] = [],
                startupCommand: String? = nil) {
        self.keepAliveInterval = keepAliveInterval
        self.keepAliveCountMax = keepAliveCountMax
        self.portForwards = portForwards
        self.startupCommand = startupCommand
    }
}

/// Carries what's needed to retry a connection once the user gives a key's passphrase.
public struct SSHPassphraseChallenge: Identifiable {
    public let id = UUID()
    public let target: SSHLogin
    public let jumps: [SSHLogin]
    /// Which login's key needs the passphrase: an index into `jumps`, or nil for the target.
    public let jumpIndex: Int?
    public let options: SSHSessionOptions
    public let terminalSize: (cols: Int, rows: Int)

    /// The login whose key is encrypted.
    public var keyOwner: SSHLogin { jumpIndex.map { jumps[$0] } ?? target }

    /// The route again, with `passphrase` for the key that asked for it.
    public func answered(with passphrase: String) -> (target: SSHLogin, jumps: [SSHLogin]) {
        guard let jumpIndex else { return (target.withPassphrase(passphrase), jumps) }
        var jumps = jumps
        jumps[jumpIndex] = jumps[jumpIndex].withPassphrase(passphrase)
        return (target, jumps)
    }
}

// MARK: - Preparing a login

/// Asks the user something during login (keyboard-interactive prompts) and shows text from
/// the server. Only terminal sessions have somewhere to ask.
struct LoginPrompter {
    let ask: KeyboardInteractiveAuthenticator.Ask
    let show: KeyboardInteractiveAuthenticator.Show
}

/// A login turned into Citadel connection settings, ready to connect.
struct PreparedLogin {
    let login: SSHLogin
    var settings: SSHClientSettings
    let capturer: CapturingHostKeyValidator?
    /// Agent keys sign on the event loop and may wait for approval, so they need a loop of
    /// their own rather than the shared one.
    let needsOwnEventLoop: Bool
}

/// Turns logins into connection settings: reads stored keys, checks agents, picks the host
/// key validator. Shared by terminal and SFTP sessions.
struct SSHLoginPreparer {
    enum Outcome {
        case ready(PreparedLogin)
        /// The key is encrypted and needs its passphrase from the user.
        case needsPassphrase
        /// Can't log in; the message says why (already in the login log).
        case failed(String)
    }

    let repository: KnownHostRepository?
    let trace: LoginTrace
    /// Nil where nobody can answer prompts (SFTP).
    let prompter: LoginPrompter?

    func prepare(_ login: SSHLogin) async -> Outcome {
        let username = login.username
        let trace = self.trace
        var needsOwnLoop = false
        var loginTimeout: TimeAmount = .seconds(30)
        let method: @Sendable () -> SSHAuthenticationMethod

        switch login.auth {
        case .password(let password):
            method = interactiveMethod(username: username, password: password)
            if prompter != nil { loginTimeout = .seconds(180) }

        case .interactive:
            guard prompter != nil else {
                trace.error("auth: no stored credential, and nothing can answer login prompts here")
                return .failed("No password or key is stored for this host. Add a credential to log in.")
            }
            method = interactiveMethod(username: username, password: nil)
            loginTimeout = .seconds(180)

        case .privateKey(let pem, let passphrase):
            let armor = SSHKeyParser.normalizedPEM(pem).split(whereSeparator: \.isNewline).first.map(String.init) ?? "(empty)"
            trace.info("key: format \(LoginTrace.quoted(armor))")
            switch StoredLoginKey.read(pem: pem, passphrase: passphrase) {
            case .key(let key):
                trace.info("key: \(key.summary); the server must list it in authorized_keys")
                method = { key.authenticationMethod(username: username, trace: trace) }
            case .needsPassphrase:
                trace.info("key: encrypted; asking the user for its passphrase (a new attempt follows)")
                return .needsPassphrase
            case .wrongPassphrase:
                trace.error("key: passphrase is incorrect, or the key isn't an Ed25519, ECDSA or RSA key")
                return .failed("Incorrect key passphrase — please try again.")
            case .invalid(let error):
                trace.error("key: \(LoginTrace.describe(error))")
                return .failed(error.localizedDescription)
            case .unsupported(let detail):
                guard prompter != nil else {
                    trace.error("key: \(detail); only those key types can log in")
                    return .failed("Only Ed25519, ECDSA and RSA keys can log in directly.")
                }
                trace.error("key: \(detail); only those are supported for direct login, so the key is NOT used "
                            + "and keyboard-interactive is tried instead")
                method = interactiveMethod(username: username, password: nil)
                loginTimeout = .seconds(180)
            }

        case .agentKey(let agentKey):
            trace.info("key: \(agentKey.algorithm ?? "unknown type") \(agentKey.fingerprint) "
                       + "\(LoginTrace.quoted(agentKey.comment)) via agent socket \(agentKey.socketPath)")
            let privateKey: NIOSSHPrivateKey
            do {
                privateKey = try await AgentBackedKey.checkedPrivateKey(for: agentKey)
                trace.info("agent: reachable and still holds the key")
            } catch {
                trace.error("agent: check failed: \(LoginTrace.describe(error))")
                return .failed(error.localizedDescription)
            }
            method = { .custom(AgentKeyAuthenticator(username: username, privateKey: privateKey, trace: trace)) }
            needsOwnLoop = true
            loginTimeout = AgentBackedKey.loginTimeout
        }

        let validator: SSHHostKeyValidator
        let capturer: CapturingHostKeyValidator?
        do {
            (validator, capturer) = try HostKeyTrust.validator(for: login.host, port: login.port,
                                                               repository: repository, trace: trace)
        } catch {
            return .failed(error.localizedDescription)
        }
        var settings = SSHClientSettings(host: login.host, port: login.port, authenticationMethod: method,
                                         hostKeyValidator: validator)
        settings.algorithms = SSHAlgorithmPolicy.algorithms
        settings.loginTimeout = loginTimeout
        settings.debugObserver = trace.protocolObserver
        return .ready(PreparedLogin(login: login, settings: settings, capturer: capturer, needsOwnEventLoop: needsOwnLoop))
    }

    private func interactiveMethod(username: String, password: String?) -> @Sendable () -> SSHAuthenticationMethod {
        let ask: KeyboardInteractiveAuthenticator.Ask = prompter?.ask ?? { @Sendable _, _ in nil }
        let show: KeyboardInteractiveAuthenticator.Show = prompter?.show ?? { @Sendable _ in }
        let trace = self.trace
        return {
            .custom(KeyboardInteractiveAuthenticator(username: username, password: password,
                                                     ask: ask, show: show, trace: trace))
        }
    }
}

// MARK: - Connecting a route

/// A server's host key stored as trusted on first use during a connection.
public struct StoredHostKey: Sendable {
    public let endpoint: String
    public let keyType: String
    public let fingerprint: String
    /// Why it couldn't be stored, if it couldn't; it was then trusted for this session only.
    public let saveError: String?
}

public enum SSHRouteError: Error, LocalizedError, CustomStringConvertible {
    /// Logging in to a jump host failed.
    case jumpHostFailed(index: Int, endpoint: String, underlying: Error)

    public var description: String {
        switch self {
        case .jumpHostFailed(let index, let endpoint, let underlying):
            let reason = ConnectionErrorText.describe(underlying)
                ?? (underlying as? LocalizedError)?.errorDescription ?? String(describing: underlying)
            return "Jump host \(index + 1) (\(endpoint)): \(reason)"
        }
    }

    public var errorDescription: String? { description }
}

/// An SSH connection to a target, plus the jump host connections it runs through. Closing it
/// closes all of them and stops the event loop it owns, if any.
public final class SSHRoute: @unchecked Sendable {
    /// The connection to the target host.
    public let client: SSHClient
    let hops: [SSHClient]
    private let ownedGroup: EventLoopGroup?
    public let storedHostKeys: [StoredHostKey]
    private let lock = NSLock()
    private var closed = false

    init(client: SSHClient, hops: [SSHClient], ownedGroup: EventLoopGroup?, storedHostKeys: [StoredHostKey]) {
        self.client = client
        self.hops = hops
        self.ownedGroup = ownedGroup
        self.storedHostKeys = storedHostKeys
    }

    public var isConnected: Bool { client.isConnected }

    public func close() async {
        let first: Bool = lock.withLock {
            defer { closed = true }
            return !closed
        }
        guard first else { return }
        try? await client.close()
        for hop in hops.reversed() { try? await hop.close() }
        try? await ownedGroup?.shutdownGracefully()
    }

    /// Connects `prepared` in order: the first directly, each next one through the one before
    /// (`ssh -J`). The last is the target. Host keys first seen are stored as trusted.
    static func connect(_ prepared: [PreparedLogin], repository: KnownHostRepository?,
                        trace: LoginTrace) async throws -> SSHRoute {
        precondition(!prepared.isEmpty)
        var prepared = prepared
        // Every connection in a route shares the first one's event loop: the tunnels are
        // channels of the connection before. So one agent key anywhere means an own loop.
        var group: EventLoopGroup?
        if prepared.contains(where: \.needsOwnEventLoop) {
            let own = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            group = own
            prepared[0].settings.group = own
        }

        var opened: [SSHClient] = []
        var stored: [StoredHostKey] = []
        do {
            for (index, step) in prepared.enumerated() {
                let isTarget = index == prepared.count - 1
                let role = isTarget ? "target" : "jump host \(index + 1)"
                if prepared.count > 1 {
                    trace.info("route: \(index == 0 ? "connecting" : "tunnelling") to \(role) \(step.login.endpoint)"
                               + (index == 0 ? "" : " through \(prepared[index - 1].login.endpoint)"))
                }
                trace.info("tcp: \(index == 0 ? "connecting to" : "direct-tcpip channel to") "
                           + "\(step.login.host):\(step.login.port), login timeout "
                           + "\(step.settings.loginTimeout.nanoseconds / 1_000_000_000)s")
                let client: SSHClient
                do {
                    if let previous = opened.last {
                        client = try await previous.jump(to: step.settings)
                    } else {
                        client = try await SSHClient.connect(to: step.settings)
                    }
                } catch {
                    // A host key mismatch is reported as such, wherever it happens.
                    if isTarget || error is InvalidHostKey { throw error }
                    trace.error("route: \(role) \(step.login.endpoint) failed: \(LoginTrace.describe(error))")
                    throw SSHRouteError.jumpHostFailed(index: index, endpoint: step.login.endpoint, underlying: error)
                }
                opened.append(client)
                if !isTarget { trace.info("route: logged in to \(role) \(step.login.endpoint)") }
                if let key = storeCapturedKey(step, repository: repository, trace: trace) { stored.append(key) }
            }
        } catch {
            for client in opened.reversed() { try? await client.close() }
            try? await group?.shutdownGracefully()
            throw error
        }
        return SSHRoute(client: opened.removeLast(), hops: opened, ownedGroup: group, storedHostKeys: stored)
    }

    /// After a first-use login, stores the key the server presented as trusted.
    private static func storeCapturedKey(_ step: PreparedLogin, repository: KnownHostRepository?,
                                         trace: LoginTrace) -> StoredHostKey? {
        // validateHostKey runs before the connect returns, so the key is captured by now.
        guard let key = step.capturer?.capturedKey, let repository else { return nil }
        let fingerprint = sshFingerprint(for: key)
        let openSSH = String(openSSHPublicKey: key)
        let keyType = String(openSSH.split(separator: " ").first ?? "unknown")
        let record = KnownHost(hostname: step.login.host, port: step.login.port, keyType: keyType,
                               keyFingerprint: fingerprint, openSSHPublicKey: openSSH)
        do {
            try repository.save(record)
            trace.info("host key: stored \(keyType) \(fingerprint) for \(step.login.host):\(step.login.port) as trusted (first use)")
            return StoredHostKey(endpoint: step.login.endpoint, keyType: keyType, fingerprint: fingerprint, saveError: nil)
        } catch {
            trace.error("host key: could not store \(keyType) \(fingerprint): \(LoginTrace.describe(error))")
            return StoredHostKey(endpoint: step.login.endpoint, keyType: keyType, fingerprint: fingerprint,
                                 saveError: error.localizedDescription)
        }
    }
}

// MARK: - Keep-alives

/// Sends `keepalive@openssh.com` every `interval` seconds, like `ssh -o ServerAliveInterval`.
/// That keeps idle connections open through firewalls and NAT, and notices a dead one: after
/// `countMax` unanswered in a row, `onDead` runs (the caller closes the route).
enum SSHKeepAlive {
    static func start(route: SSHRoute, interval: Int, countMax: Int, endpoint: String,
                      onDead: @escaping @Sendable () async -> Void) -> Task<Void, Never>? {
        guard interval > 0 else { return nil }
        return Task.detached {
            var missed = 0
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval) * 1_000_000_000)
                guard !Task.isCancelled, route.isConnected else { return }
                if await answered(route.client, within: interval) {
                    missed = 0
                    continue
                }
                missed += 1
                LoginTrace.event("keep-alive: no answer from \(endpoint) (\(missed) of \(countMax))", level: .error)
                if missed >= countMax {
                    LoginTrace.event("keep-alive: \(endpoint) stopped answering; closing the connection", level: .error)
                    await onDead()
                    return
                }
            }
        }
    }

    /// Whether the server answers one keep-alive within `seconds`. Doesn't wait any longer
    /// than that, even if the request itself never completes.
    private static func answered(_ client: SSHClient, within seconds: Int) async -> Bool {
        let gate = ResumeOnce()
        return await withCheckedContinuation { continuation in
            Task {
                let ok = (try? await client.sendKeepAlive()) != nil
                gate.resume(continuation, with: ok)
            }
            Task {
                try? await Task.sleep(nanoseconds: UInt64(max(1, seconds)) * 1_000_000_000)
                gate.resume(continuation, with: false)
            }
        }
    }
}

/// Resumes a continuation the first time only.
final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func resume<T>(_ continuation: CheckedContinuation<T, Never>, with value: T) {
        let first: Bool = lock.withLock {
            defer { done = true }
            return !done
        }
        if first { continuation.resume(returning: value) }
    }
}
