import Foundation
import SwiftUI
import AppKit
import CryptoKit
import SSHoeboxCore

/// Where the main window is, and requests to go somewhere else: Quick Connect, `ssh://`
/// links, the menu bar and the host list's context menu all open hosts through it.
/// Owned by `SSHoeboxApp` and injected as an environment object.
@MainActor
final class AppNavigator: ObservableObject {
    enum HostAction: Equatable {
        /// Show the host's terminal, opening a session if none is open.
        case terminal
        /// Open another terminal tab.
        case newTerminal
        /// Show the host's files (SFTP).
        case files
        /// Just show the host.
        case show
    }

    struct HostRoute: Hashable {
        let hostId: String
    }

    /// A host to perform an action on once its detail view is showing.
    struct PendingHostAction: Equatable {
        let hostId: String
        let action: HostAction
        let id = UUID()
    }

    /// Values for a new host, from an `ssh://` link no saved host matches.
    struct NewHostDraft: Identifiable, Equatable {
        let id = UUID()
        let hostname: String
        let port: Int
        let user: String
    }

    @Published var sidebar: MainView.SidebarItem? = .hosts
    @Published var hostPath: [HostRoute] = []
    @Published var showQuickConnect = false
    @Published private(set) var pendingAction: PendingHostAction?
    @Published var pendingNewHost: NewHostDraft?
    /// An `ssh://` link that arrived while the vault was locked, handled after unlock.
    private var pendingURL: URL?

    func open(hostId: String, action: HostAction) {
        sidebar = .hosts
        if hostPath.last?.hostId != hostId {
            hostPath = [HostRoute(hostId: hostId)]
        }
        pendingAction = PendingHostAction(hostId: hostId, action: action)
        NSApp?.activate(ignoringOtherApps: true)
    }

    /// The pending action for `hostId`, if any, which is then cleared.
    func takeAction(for hostId: String) -> HostAction? {
        guard let pending = pendingAction, pending.hostId == hostId else { return nil }
        pendingAction = nil
        return pending.action
    }

    // MARK: - ssh:// links

    /// Opens `ssh://[user@]host[:port]`: the matching saved host connects, otherwise the New
    /// Host sheet opens filled in. With the vault locked, it waits for the unlock.
    func handle(url: URL, dbManager: DatabaseManager?, vaultKey: SymmetricKey?) {
        guard let link = SSHLink(url: url) else { return }
        guard let dbManager, let vaultKey else {
            pendingURL = url
            NSApp?.activate(ignoringOtherApps: true)
            return
        }
        let hosts = (try? HostRepository(dbManager: dbManager).getAll()) ?? []
        if let host = link.bestMatch(in: hosts, vaultKey: vaultKey) {
            open(hostId: host.id, action: .terminal)
        } else {
            sidebar = .hosts
            hostPath = []
            pendingNewHost = NewHostDraft(hostname: link.host, port: link.port ?? 22, user: link.user ?? "")
            NSApp?.activate(ignoringOtherApps: true)
        }
    }

    /// Handles a link that arrived while locked.
    func vaultDidUnlock(dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        guard let url = pendingURL else { return }
        pendingURL = nil
        handle(url: url, dbManager: dbManager, vaultKey: vaultKey)
    }

    func vaultDidLock() {
        hostPath = []
        pendingAction = nil
        showQuickConnect = false
        pendingNewHost = nil
    }
}

/// An `ssh://` URL (RFC draft "ssh URI"): `ssh://[user[;params]@]host[:port]`.
struct SSHLink: Equatable {
    let user: String?
    let host: String
    let port: Int?

    init(user: String?, host: String, port: Int?) {
        self.user = user
        self.host = host
        self.port = port
    }

    init?(url: URL) {
        guard let scheme = url.scheme?.lowercased(), ["ssh", "sshoebox"].contains(scheme),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let host = components.host, !host.isEmpty else { return nil }
        // A user may carry connection parameters after ';' (e.g. a fingerprint); not used.
        let user = components.user?.split(separator: ";").first.map(String.init)
        self.user = user?.removingPercentEncoding ?? user
        self.host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        self.port = components.port
    }

    /// The saved host this link names: same address and port, and the same user if the link
    /// has one. The most recently used wins when several match.
    func bestMatch(in hosts: [SavedHost], vaultKey: SymmetricKey) -> SavedHost? {
        let wantedPort = port ?? 22
        return hosts.filter { saved in
            saved.decryptedHostname(using: vaultKey).caseInsensitiveCompare(host) == .orderedSame
                && saved.port == wantedPort
                && (user == nil || saved.decryptedUser(using: vaultKey) == user)
        }
        .max { ($0.lastConnectedAt ?? .distantPast) < ($1.lastConnectedAt ?? .distantPast) }
    }
}
