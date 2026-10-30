import Foundation
import SwiftUI
import SSHoeboxCore
import CryptoKit
import Combine

/// A long-lived registry that holds one TerminalSessionStore per host.
/// Owned as a @StateObject on SSHoeboxApp and injected as an @EnvironmentObject
/// so session stores survive sidebar navigation, host-list refreshes, and
/// any other view recreation while the vault is unlocked. Every store holds the
/// vault key, so `removeAll()` runs when the vault locks.
@MainActor
class TerminalSessionRegistry: ObservableObject {
    private var stores: [String: TerminalSessionStore] = [:]
    /// Per store: republishes session connection-state changes so views showing
    /// `totalActiveConnections` (e.g. the menu bar) stay current.
    private var stateObservers: [String: AnyCancellable] = [:]

    var totalActiveConnections: Int {
        stores.values.reduce(0) { total, store in
            total + store.sessions.filter { session in
                switch session.manager.connectionState {
                case .connected, .connecting: return true
                default: return false
                }
            }.count
        }
    }

    /// Returns the existing store for a host, or creates one if none exists.
    /// An existing store picks up `host` as passed, so edits to the host apply to new sessions.
    func store(for host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey) -> TerminalSessionStore {
        if let existing = stores[host.id] {
            existing.host = host
            return existing
        }
        let newStore = TerminalSessionStore(host: host, dbManager: dbManager, vaultKey: vaultKey)
        stores[host.id] = newStore
        stateObservers[host.id] = newStore.$sessions
            .map { sessions in
                Publishers.MergeMany(sessions.map { $0.manager.$connectionState.map { _ in () } })
                    .prepend(())
            }
            .switchToLatest()
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.objectWillChange.send() }
        return newStore
    }

    /// Removes the store for a host (call when a host is deleted).
    func removeStore(for hostId: String) {
        if let store = stores[hostId] {
            store.disconnectAll()
        }
        stores.removeValue(forKey: hostId)
        stateObservers.removeValue(forKey: hostId)
        objectWillChange.send()
    }

    /// Ends every session and drops every store, releasing their copies of the vault key
    /// and database handle. Called when the vault locks.
    func removeAll() {
        stores.values.forEach { $0.disconnectAll() }
        stores.removeAll()
        stateObservers.removeAll()
        objectWillChange.send()
    }
}

/// Owns SSH terminal sessions for a single host.
/// Kept alive by TerminalSessionRegistry regardless of view recreation.
@MainActor
class TerminalSessionStore: ObservableObject {
    @Published var sessions: [TerminalSession] = []
    @Published var selectedSessionId: UUID?

    /// Read at connect time, so new sessions use the latest saved address and user.
    fileprivate(set) var host: SavedHost
    private let dbManager: DatabaseManager
    private let vaultKey: SymmetricKey
    private var credentialsViewModel: CredentialsViewModel

    init(host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.host = host
        self.dbManager = dbManager
        self.vaultKey = vaultKey
        self.credentialsViewModel = CredentialsViewModel(
            dbManager: dbManager,
            vaultKey: vaultKey,
            hostId: host.id
        )
    }

    // MARK: - Session Lifecycle

    func openNewSession() {
        credentialsViewModel.fetchCredentials()

        let manager = SSHSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: dbManager)
        let sessionNumber = sessions.count + 1
        let session = TerminalSession(
            id: UUID(),
            title: "Terminal \(sessionNumber)",
            manager: manager
        )
        sessions.append(session)
        selectedSessionId = session.id

        let hostId = host.id
        let db = dbManager
        manager.onConnected = {
            Task {
                try? HostRepository(dbManager: db).updateLastConnected(hostId: hostId)
            }
        }

        Task {
            await connectSession(manager: manager)
        }
    }

    func reconnect(_ session: TerminalSession) {
        credentialsViewModel.fetchCredentials()
        Task {
            await connectSession(manager: session.manager)
        }
    }

    /// Called by the UI after the user supplies a passphrase for an encrypted key.
    func submitPassphrase(_ passphrase: String, for session: TerminalSession) {
        guard let challenge = session.manager.passphraseChallenge else { return }
        session.manager.passphraseChallenge = nil
        Task {
            await session.manager.connect(
                host: challenge.host,
                port: challenge.port,
                username: challenge.username,
                pemKey: challenge.pemKey,
                passphrase: passphrase,
                terminalSize: challenge.terminalSize
            )
        }
    }

    func closeSession(_ session: TerminalSession) {
        session.manager.disconnect()
        sessions.removeAll { $0.id == session.id }
        if selectedSessionId == session.id {
            selectedSessionId = sessions.last?.id
        }
    }

    func select(_ session: TerminalSession) {
        selectedSessionId = session.id
    }

    func disconnectAll() {
        sessions.forEach { $0.manager.disconnect() }
        sessions.removeAll()
        selectedSessionId = nil
    }

    // MARK: - Connection

    private func connectSession(manager: SSHSessionManager) async {
        let hostname = host.decryptedHostname(using: vaultKey)
        let defaultUser = host.decryptedUser(using: vaultKey)
        let port = host.port

        if let cred = credentialsViewModel.credentials.first(where: { $0.type == "password" }) {
            let credUser = cred.decryptedUsername(using: vaultKey)
            let username = credUser.isEmpty ? defaultUser : credUser
            if let password = credentialsViewModel.decrypt(credential: cred) {
                await manager.connect(host: hostname, port: port, username: username, password: password)
            } else {
                manager.log("ERROR: Decryption failed for password.", color: "31")
                await manager.connectInteractive(host: hostname, port: port, username: username)
            }
        } else if let cred = credentialsViewModel.credentials.first(where: { $0.type == "key" }) {
            let credUser = cred.decryptedUsername(using: vaultKey)
            let username = credUser.isEmpty ? defaultUser : credUser
            if let pem = credentialsViewModel.decrypt(credential: cred) {
                await manager.connect(host: hostname, port: port, username: username, pemKey: pem)
            } else {
                manager.log("ERROR: Decryption failed for private key.", color: "31")
                await manager.connectInteractive(host: hostname, port: port, username: username)
            }
        } else if let cred = credentialsViewModel.credentials.first(where: { $0.type == SSHAgentKeyReference.credentialType }) {
            let credUser = cred.decryptedUsername(using: vaultKey)
            let username = credUser.isEmpty ? defaultUser : credUser
            if let agentKey = credentialsViewModel.agentKey(for: cred) {
                await manager.connect(host: hostname, port: port, username: username, agentKey: agentKey)
            } else {
                manager.log("ERROR: Could not read the SSH agent key for this credential.", color: "31")
                await manager.connectInteractive(host: hostname, port: port, username: username)
            }
        } else {
            await manager.connectInteractive(host: hostname, port: port, username: defaultUser)
        }
    }
}

// MARK: - Session Model

struct TerminalSession: Identifiable {
    let id: UUID
    let title: String
    let manager: SSHSessionManager
}
