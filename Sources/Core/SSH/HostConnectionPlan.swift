import Foundation
import CryptoKit

/// Everything needed to connect to a saved host: its login, the jump hosts on the way
/// (outermost first), and the session options.
public struct HostConnectionPlan {
    public var target: SSHLogin
    public var jumps: [SSHLogin]
    public var options: SSHSessionOptions
    /// Problems found while resolving (a credential that wouldn't decrypt, a missing jump
    /// host). Connecting still goes ahead; the caller shows these in the terminal.
    public var warnings: [String]
}

public enum HostConnectionPlanError: LocalizedError {
    case jumpLoop([String])
    case tooManyJumps

    public var errorDescription: String? {
        switch self {
        case .jumpLoop(let names):
            return "The jump hosts go round in a loop (\(names.joined(separator: " → "))). Change one of them in Edit Host."
        case .tooManyJumps:
            return "More than \(HostConnectionPlanner.maxJumps) jump hosts in a row. Shorten the chain in Edit Host."
        }
    }
}

/// Builds connection plans from the vault: decrypts the address, picks the credential the
/// same way everywhere (password, then key, then agent key, else keyboard-interactive) and
/// follows the jump host chain.
public struct HostConnectionPlanner {
    public static let maxJumps = 8

    private let hosts: HostRepository
    private let credentials: CredentialRepository
    private let vaultKey: SymmetricKey

    public init(dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.hosts = HostRepository(dbManager: dbManager)
        self.credentials = CredentialRepository(dbManager: dbManager)
        self.vaultKey = vaultKey
    }

    public func plan(for host: SavedHost) throws -> HostConnectionPlan {
        var warnings: [String] = []
        let options = host.decryptedOptions(using: vaultKey)
        let target = login(for: host, warnings: &warnings)

        // Follow jumpHostId back from the target: each jump host may have one of its own.
        var jumps: [SSHLogin] = []
        var seen: [String] = [host.id]
        var names = [host.decryptedName(using: vaultKey)]
        var nextId = options.jumpHostId
        while let id = nextId {
            if seen.contains(id) {
                let name = (try? hosts.get(id: id))??.decryptedName(using: vaultKey) ?? id
                throw HostConnectionPlanError.jumpLoop(names.reversed() + [name])
            }
            guard jumps.count < Self.maxJumps else { throw HostConnectionPlanError.tooManyJumps }
            guard let jumpHost = try hosts.get(id: id) else {
                warnings.append("The jump host set for \(names.last ?? "this host") no longer exists; connecting directly.")
                break
            }
            seen.append(id)
            names.append(jumpHost.decryptedName(using: vaultKey))
            jumps.insert(login(for: jumpHost, warnings: &warnings), at: 0)
            nextId = jumpHost.decryptedOptions(using: vaultKey).jumpHostId
        }

        let preferred = SSHSessionOptions.preferredKeepAliveInterval
        let sessionOptions = SSHSessionOptions(
            keepAliveInterval: options.keepAliveInterval ?? preferred,
            portForwards: options.portForwards,
            startupCommand: options.effectiveStartupCommand
        )
        return HostConnectionPlan(target: target, jumps: jumps, options: sessionOptions, warnings: warnings)
    }

    /// The login for one host from its stored credentials.
    public func login(for host: SavedHost) -> SSHLogin {
        var ignored: [String] = []
        return login(for: host, warnings: &ignored)
    }

    private func login(for host: SavedHost, warnings: inout [String]) -> SSHLogin {
        let hostname = host.decryptedHostname(using: vaultKey)
        let defaultUser = host.decryptedUser(using: vaultKey)
        let stored = (try? credentials.getForHost(hostId: host.id)) ?? []
        let name = host.decryptedName(using: vaultKey)

        func user(_ credential: Credential) -> String {
            let username = credential.decryptedUsername(using: vaultKey)
            return username.isEmpty ? defaultUser : username
        }
        func secret(_ credential: Credential) -> String? {
            (try? credentials.decryptSecret(for: credential, vaultKey: vaultKey)).flatMap { String(data: $0, encoding: .utf8) }
        }

        if let credential = stored.first(where: { $0.type == "password" }) {
            if let password = secret(credential) {
                return SSHLogin(host: hostname, port: host.port, username: user(credential), auth: .password(password))
            }
            warnings.append("\(name): the stored password could not be decrypted; using keyboard-interactive.")
            LoginTrace.event("credential \(credential.id): stored password could not be decrypted; "
                             + "falling back to keyboard-interactive", level: .error)
            return SSHLogin(host: hostname, port: host.port, username: user(credential), auth: .interactive)
        }
        if let credential = stored.first(where: { $0.type == "key" }) {
            if let pem = secret(credential) {
                return SSHLogin(host: hostname, port: host.port, username: user(credential),
                                auth: .privateKey(pem: pem, passphrase: nil))
            }
            warnings.append("\(name): the stored private key could not be decrypted; using keyboard-interactive.")
            LoginTrace.event("credential \(credential.id): stored private key could not be decrypted; "
                             + "falling back to keyboard-interactive", level: .error)
            return SSHLogin(host: hostname, port: host.port, username: user(credential), auth: .interactive)
        }
        if let credential = stored.first(where: { $0.type == SSHAgentKeyReference.credentialType }) {
            if let data = try? credentials.decryptSecret(for: credential, vaultKey: vaultKey),
               let reference = try? SSHAgentKeyReference.decode(data) {
                return SSHLogin(host: hostname, port: host.port, username: user(credential), auth: .agentKey(reference))
            }
            warnings.append("\(name): the SSH agent key reference could not be read; using keyboard-interactive.")
            LoginTrace.event("credential \(credential.id): SSH agent key reference could not be read; "
                             + "falling back to keyboard-interactive", level: .error)
            return SSHLogin(host: hostname, port: host.port, username: user(credential), auth: .interactive)
        }
        return SSHLogin(host: hostname, port: host.port, username: defaultUser, auth: .interactive)
    }
}
