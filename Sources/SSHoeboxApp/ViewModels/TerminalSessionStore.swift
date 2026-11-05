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
    /// Sessions whose typed input goes to all of them (see `broadcast(_:)`).
    @Published private(set) var broadcastIDs: Set<UUID> = []
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

    /// Every open terminal session, grouped by host in the order the hosts were opened.
    var allSessions: [TerminalSession] {
        storeOrder.compactMap { stores[$0] }.flatMap(\.sessions)
    }
    private var storeOrder: [String] = []

    // MARK: - Broadcast

    func isBroadcasting(_ session: TerminalSession) -> Bool {
        broadcastIDs.contains(session.id)
    }

    func setBroadcast(_ on: Bool, for sessions: [TerminalSession]) {
        for session in sessions {
            if on { broadcastIDs.insert(session.id) } else { broadcastIDs.remove(session.id) }
        }
    }

    /// Sends input to every session in the broadcast group.
    func broadcast(_ data: Data) {
        for session in allSessions where broadcastIDs.contains(session.id) {
            session.manager.send(data)
        }
    }

    private func pruneBroadcast() {
        let alive = Set(allSessions.map(\.id))
        broadcastIDs.formIntersection(alive)
    }

    /// Returns the existing store for a host, or creates one if none exists.
    /// An existing store picks up `host` as passed, so edits to the host apply to new sessions.
    func store(for host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey) -> TerminalSessionStore {
        if let existing = stores[host.id] {
            existing.host = host
            return existing
        }
        let newStore = TerminalSessionStore(host: host, dbManager: dbManager, vaultKey: vaultKey)
        newStore.registry = self
        stores[host.id] = newStore
        storeOrder.append(host.id)
        stateObservers[host.id] = newStore.$sessions
            .handleEvents(receiveOutput: { [weak self] _ in
                DispatchQueue.main.async { self?.pruneBroadcast() }
            })
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
        storeOrder.removeAll { $0 == hostId }
        stateObservers.removeValue(forKey: hostId)
        pruneBroadcast()
        objectWillChange.send()
    }

    /// The store of an open host, if any.
    func existingStore(for hostId: String) -> TerminalSessionStore? {
        stores[hostId]
    }

    /// Ends every session and drops every store, releasing their copies of the vault key
    /// and database handle. Called when the vault locks.
    func removeAll() {
        stores.values.forEach { $0.disconnectAll() }
        stores.removeAll()
        storeOrder.removeAll()
        stateObservers.removeAll()
        broadcastIDs.removeAll()
        objectWillChange.send()
    }
}

/// Owns SSH terminal sessions for a single host.
/// Kept alive by TerminalSessionRegistry regardless of view recreation.
@MainActor
class TerminalSessionStore: ObservableObject {
    @Published var sessions: [TerminalSession] = []
    @Published var selectedSessionId: UUID?
    private var nextSessionNumber = 0

    /// Read at connect time, so new sessions use the latest saved address and user.
    fileprivate(set) var host: SavedHost
    weak var registry: TerminalSessionRegistry?
    /// How this host's sessions are laid out: one at a time in tabs, or all side by side.
    @Published var isSplit = false
    private let dbManager: DatabaseManager
    private let vaultKey: SymmetricKey

    init(host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.host = host
        self.dbManager = dbManager
        self.vaultKey = vaultKey
    }

    // MARK: - Session Lifecycle

    func openNewSession() {
        let manager = SSHSessionManager()
        manager.knownHostRepository = KnownHostRepository(dbManager: dbManager)
        nextSessionNumber += 1
        let session = TerminalSession(
            hostId: host.id,
            hostName: host.decryptedName(using: vaultKey),
            title: "Terminal \(nextSessionNumber)",
            manager: manager
        )
        session.registry = registry
        if SessionRecorder.recordsAutomatically { session.startRecording() }
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
        Task {
            await connectSession(manager: session.manager)
        }
    }

    /// Called by the UI after the user supplies a passphrase for an encrypted key.
    func submitPassphrase(_ passphrase: String, for session: TerminalSession) {
        guard let challenge = session.manager.passphraseChallenge else { return }
        session.manager.passphraseChallenge = nil
        Task {
            await session.manager.connect(answering: challenge, passphrase: passphrase)
        }
    }

    func closeSession(_ session: TerminalSession) {
        session.close()
        sessions.removeAll { $0.id == session.id }
        if selectedSessionId == session.id {
            selectedSessionId = sessions.last?.id
        }
    }

    func select(_ session: TerminalSession) {
        selectedSessionId = session.id
    }

    func disconnectAll() {
        sessions.forEach { $0.close() }
        sessions.removeAll()
        selectedSessionId = nil
    }

    // MARK: - Connection

    private func connectSession(manager: SSHSessionManager) async {
        let planner = HostConnectionPlanner(dbManager: dbManager, vaultKey: vaultKey)
        do {
            let plan = try planner.plan(for: host)
            for warning in plan.warnings { manager.log("⚠  \(warning)", color: "33") }
            await manager.connect(plan.target, via: plan.jumps, options: plan.options)
        } catch {
            manager.log("⚠  \(error.localizedDescription)", color: "31")
            LoginTrace.event("connect: \(error.localizedDescription)", level: .error)
        }
    }
}

extension TerminalSessionStore {
    /// Snippets for this host (its own, then the global ones), decrypted.
    func snippets() -> [(id: String, name: String, command: String, isGlobal: Bool)] {
        let stored = (try? SnippetRepository(dbManager: dbManager).snippets(forHost: host.id)) ?? []
        return stored.map { ($0.id, $0.decryptedName(using: vaultKey), $0.decryptedCommand(using: vaultKey), $0.hostId == nil) }
    }

    var snippetContext: (dbManager: DatabaseManager, vaultKey: SymmetricKey) { (dbManager, vaultKey) }
}
