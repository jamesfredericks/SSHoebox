import Foundation
import SwiftUI
import SSHoeboxCore
import CryptoKit

/// A stable, long-lived store for SSH terminal sessions for a single host.
/// Owned as a @StateObject by HostDetailView so sessions survive tab switches
/// and other transient view updates.
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

    /// Opens a new SSH session tab. Called automatically when the terminal
    /// tab is first shown (if no sessions exist) and by the "+" button.
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
