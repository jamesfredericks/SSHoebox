import Foundation
import SwiftUI
import SSHoeboxCore
import CryptoKit

/// A long-lived registry that holds one TerminalSessionStore per host.
/// Owned as a @StateObject on MainView and injected as an @EnvironmentObject
/// so session stores survive sidebar navigation, host-list refreshes, and
/// any other view recreation throughout the app's lifetime.
@MainActor
class TerminalSessionRegistry: ObservableObject {
    private var stores: [String: TerminalSessionStore] = [:]

    /// Returns the existing store for a host, or creates one if none exists.
    func store(for host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey) -> TerminalSessionStore {
        if let existing = stores[host.id] {
            return existing
        }
        let newStore = TerminalSessionStore(host: host, dbManager: dbManager, vaultKey: vaultKey)
        stores[host.id] = newStore
        return newStore
    }

    /// Removes the store for a host (call when a host is deleted).
    func removeStore(for hostId: String) {
        if let store = stores[hostId] {
            store.disconnectAll()
        }
        stores.removeValue(forKey: hostId)
    }
}

/// Owns SSH terminal sessions for a single host.
/// Kept alive by TerminalSessionRegistry regardless of view recreation.
@MainActor
class TerminalSessionStore: ObservableObject {
    @Published var sessions: [TerminalSession] = []
    @Published var selectedSessionId: UUID?

    private let host: SavedHost
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
        let sessionNumber = sessions.count + 1
        let session = TerminalSession(
            id: UUID(),
            title: "Terminal \(sessionNumber)",
            manager: manager
        )
        sessions.append(session)
        selectedSessionId = session.id

        Task {
            await connectSession(manager: manager)
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
            await manager.connectInteractive(host: hostname, port: port, username: username)
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
