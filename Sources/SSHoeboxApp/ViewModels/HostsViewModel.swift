import Foundation
import Combine
import SSHoeboxCore
import CryptoKit

@MainActor
class HostsViewModel: ObservableObject {
    @Published var hosts: [SavedHost] = []
    @Published var groups: [HostGroup] = []
    @Published var errorMessage: String?
    @Published var searchQuery: String = ""
    @Published var collapsedGroups: Set<String> = []

    /// Called with a host's id after it is deleted, so its open sessions can be ended.
    var onHostDeleted: ((String) -> Void)?

    private let dbManager: DatabaseManager
    private let repository: HostRepository
    private let groupRepository: GroupRepository
    private let credentialRepository: CredentialRepository
    private let vaultKey: SymmetricKey
    private var cancellables = Set<AnyCancellable>()

    init(dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.dbManager = dbManager
        self.repository = HostRepository(dbManager: dbManager)
        self.groupRepository = GroupRepository(dbManager: dbManager)
        self.credentialRepository = CredentialRepository(dbManager: dbManager)
        self.vaultKey = vaultKey
        fetchGroups()
        fetchHosts()
        NotificationCenter.default.publisher(for: .vaultDidSync)
            .sink { [weak self] _ in
                self?.fetchGroups()
                self?.fetchHosts()
            }
            .store(in: &cancellables)
    }

    // MARK: - Host Fetching

    func fetchHosts() {
        do {
            hosts = try repository.getAll()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to fetch hosts: \(error.localizedDescription)"
        }
    }

    // MARK: - Grouped Hosts

    /// Returns hosts arranged by group (in sort order), with ungrouped hosts last.
    /// Filtered by searchQuery when non-empty.
    var hostsGrouped: [(group: HostGroup?, hosts: [SavedHost])] {
        let filtered = filteredHosts
        var result: [(group: HostGroup?, hosts: [SavedHost])] = []

        for group in groups {
            let members = filtered.filter { $0.groupId == group.id }
            if !members.isEmpty {
                result.append((group: group, hosts: members))
            }
        }

        let ungrouped = filtered.filter { $0.groupId == nil }
        if !ungrouped.isEmpty {
            result.append((group: nil, hosts: ungrouped))
        }

        return result
    }

    /// Favorite hosts, by name. They're also listed in their group.
    var favoriteHosts: [SavedHost] {
        filteredHosts.filter { options(for: $0).isFavorite }
            .sorted { $0.decryptedName(using: vaultKey).localizedCaseInsensitiveCompare($1.decryptedName(using: vaultKey)) == .orderedAscending }
    }

    private var filteredHosts: [SavedHost] {
        guard !searchQuery.trimmingCharacters(in: .whitespaces).isEmpty else { return hosts }
        return hosts.filter { HostSearch.matches($0, query: searchQuery, vaultKey: vaultKey) }
    }

    func options(for host: SavedHost) -> HostOptions {
        host.decryptedOptions(using: vaultKey)
    }

    func name(of host: SavedHost) -> String {
        host.decryptedName(using: vaultKey)
    }

    func toggleCollapse(groupId: String) {
        if collapsedGroups.contains(groupId) {
            collapsedGroups.remove(groupId)
        } else {
            collapsedGroups.insert(groupId)
        }
    }

    // MARK: - Host CRUD

    @discardableResult
    func addHost(name: String, hostname: String, port: Int, protocolType: String, user: String,
                 groupId: String? = nil, options: HostOptions = HostOptions(),
                 credentialType: String = "none", credentialSecret: String = "") -> SavedHost? {
        guard var host = try? SavedHost.encrypted(name: name, hostname: hostname, port: port,
                                                  protocolType: protocolType, user: user,
                                                  groupId: groupId, using: vaultKey),
              (try? host.setOptions(options, using: vaultKey)) != nil else {
            errorMessage = "Failed to encrypt host data."
            return nil
        }
        do {
            try repository.save(host)

            if credentialType != "none" && !credentialSecret.isEmpty {
                if let secretData = credentialSecret.data(using: .utf8) {
                    _ = try credentialRepository.createCredential(
                        hostId: host.id,
                        username: user,
                        type: credentialType,
                        secret: secretData,
                        vaultKey: vaultKey
                    )
                }
            }

            fetchHosts()
            return host
        } catch {
            errorMessage = "Failed to save host: \(error.localizedDescription)"
            return nil
        }
    }

    /// Imports `~/.ssh/config` entries. `ProxyJump` hops become jump hosts: an imported alias
    /// or an existing host with that name or address is used, otherwise a host is added for
    /// the hop. `LocalForward` and `ServerAliveInterval` become the host's tunnels and
    /// keep-alive. Returns how many hosts were added.
    @discardableResult
    func importConfigHosts(_ entries: [SSHConfigParser.ConfigHost]) -> Int {
        var added = 0
        var idForAlias: [String: String] = [:]
        for entry in entries {
            var options = HostOptions()
            options.portForwards = entry.localForwards
            options.keepAliveInterval = entry.serverAliveInterval
            if let host = addHost(name: entry.alias, hostname: entry.hostname, port: entry.port,
                                  protocolType: "ssh", user: entry.user, options: options) {
                idForAlias[entry.alias.lowercased()] = host.id
                added += 1
            }
        }

        func hostId(forHop spec: String) -> String? {
            let (user, hopHost, port) = SSHConfigParser.parseJumpSpec(spec)
            if user == nil, port == nil, let id = idForAlias[hopHost.lowercased()] { return id }
            let wanted = hopHost.lowercased()
            if let existing = hosts.first(where: { host in
                (host.decryptedName(using: vaultKey).lowercased() == wanted
                    || host.decryptedHostname(using: vaultKey).lowercased() == wanted)
                    && (port == nil || host.port == port)
                    && (user == nil || host.decryptedUser(using: vaultKey) == user)
            }) {
                return existing.id
            }
            guard let created = addHost(name: spec, hostname: hopHost, port: port ?? 22,
                                        protocolType: "ssh", user: user ?? "") else { return nil }
            idForAlias[spec.lowercased()] = created.id
            added += 1
            return created.id
        }

        for entry in entries where !entry.proxyJump.isEmpty {
            guard let targetId = idForAlias[entry.alias.lowercased()] else { continue }
            let hopIds = entry.proxyJump.compactMap(hostId(forHop:))
            guard hopIds.count == entry.proxyJump.count, let last = hopIds.last else { continue }
            setJumpHost(of: targetId, to: last, onlyIfUnset: false)
            for index in hopIds.indices.dropFirst() {
                setJumpHost(of: hopIds[index], to: hopIds[index - 1], onlyIfUnset: true)
            }
        }
        fetchHosts()
        return added
    }

    private func setJumpHost(of hostId: String, to jumpId: String, onlyIfUnset: Bool) {
        guard hostId != jumpId, let host = hosts.first(where: { $0.id == hostId }) else { return }
        if onlyIfUnset, options(for: host).jumpHostId != nil { return }
        updateOptions(of: host) { $0.jumpHostId = jumpId }
    }

    /// Saves the host's fields. `options` nil keeps the stored options as they are.
    func updateHost(id: String, name: String, hostname: String, port: Int,
                    protocolType: String, user: String, groupId: String? = nil,
                    options: HostOptions? = nil) {
        guard let existingHost = hosts.first(where: { $0.id == id }) else {
            errorMessage = "Host not found"
            return
        }

        guard var updatedHost = try? SavedHost.encrypted(
            id: id,
            name: name,
            hostname: hostname,
            port: port,
            protocolType: protocolType,
            user: user,
            groupId: groupId,
            createdAt: existingHost.createdAt,
            updatedAt: Date(),
            lastConnectedAt: existingHost.lastConnectedAt,
            using: vaultKey
        ) else {
            errorMessage = "Failed to encrypt host data."
            return
        }
        updatedHost.encryptedOptions = existingHost.encryptedOptions
        if let options {
            guard (try? updatedHost.setOptions(options, using: vaultKey)) != nil else {
                errorMessage = "Failed to encrypt host data."
                return
            }
        }

        do {
            try repository.save(updatedHost)
            fetchHosts()
        } catch {
            errorMessage = "Failed to update host: \(error.localizedDescription)"
        }
    }

    /// Changes only the host's options (favorite, tags, ...).
    func updateOptions(of host: SavedHost, _ change: (inout HostOptions) -> Void) {
        guard var current = hosts.first(where: { $0.id == host.id }) else { return }
        var options = current.decryptedOptions(using: vaultKey)
        change(&options)
        do {
            try current.setOptions(options, using: vaultKey)
            current.updatedAt = Date()
            try repository.save(current)
            fetchHosts()
        } catch {
            errorMessage = "Failed to update host: \(error.localizedDescription)"
        }
    }

    func toggleFavorite(_ host: SavedHost) {
        updateOptions(of: host) { $0.isFavorite.toggle() }
    }

    /// Copies a host with its options and credentials, named "<name> copy". Fields are
    /// encrypted for the new row, so they're decrypted and sealed again rather than copied.
    @discardableResult
    func duplicateHost(_ host: SavedHost) -> SavedHost? {
        do {
            var copy = try SavedHost.encrypted(
                name: host.decryptedName(using: vaultKey) + " copy",
                hostname: host.decryptedHostname(using: vaultKey),
                port: host.port, protocolType: host.protocolType,
                user: host.decryptedUser(using: vaultKey), groupId: host.groupId, using: vaultKey)
            var options = host.decryptedOptions(using: vaultKey)
            options.portForwards = options.portForwards.map {
                PortForward(localPort: $0.localPort, remoteHost: $0.remoteHost, remotePort: $0.remotePort,
                            autoStart: $0.autoStart, bindAddress: $0.bindAddress)
            }
            options.isFavorite = false
            try copy.setOptions(options, using: vaultKey)
            try repository.save(copy)
            for credential in try credentialRepository.getForHost(hostId: host.id) {
                let secret = try credentialRepository.decryptSecret(for: credential, vaultKey: vaultKey)
                _ = try credentialRepository.createCredential(
                    hostId: copy.id, username: credential.decryptedUsername(using: vaultKey),
                    type: credential.type, secret: secret, vaultKey: vaultKey,
                    isInteractive: credential.isInteractive)
            }
            fetchHosts()
            return copy
        } catch {
            errorMessage = "Failed to duplicate host: \(error.localizedDescription)"
            return nil
        }
    }

    func deleteHost(at offsets: IndexSet) {
        offsets.forEach { index in
            let host = hosts[index]
            do {
                try repository.delete(host)
                onHostDeleted?(host.id)
            } catch {
                errorMessage = "Failed to delete host: \(error.localizedDescription)"
            }
        }
        fetchHosts()
    }

    func deleteHost(_ host: SavedHost) {
        do {
            try repository.delete(host)
            onHostDeleted?(host.id)
            fetchHosts()
        } catch {
            errorMessage = "Failed to delete host: \(error.localizedDescription)"
        }
    }

    // MARK: - Group CRUD

    func fetchGroups() {
        do {
            groups = try groupRepository.getAll()
        } catch {
            errorMessage = "Failed to fetch groups: \(error.localizedDescription)"
        }
    }

    func addGroup(name: String) {
        let group = HostGroup(name: name, sortOrder: groups.count)
        do {
            try groupRepository.save(group)
            fetchGroups()
        } catch {
            errorMessage = "Failed to create group: \(error.localizedDescription)"
        }
    }

    func updateGroup(_ group: HostGroup, name: String) {
        var updated = group
        updated.name = name
        updated.updatedAt = Date()
        do {
            try groupRepository.save(updated)
            fetchGroups()
        } catch {
            errorMessage = "Failed to update group: \(error.localizedDescription)"
        }
    }

    func deleteGroup(_ group: HostGroup) {
        do {
            try groupRepository.delete(group)
            fetchGroups()
            fetchHosts() // Hosts with this groupId become ungrouped (DB cascade sets null)
        } catch {
            errorMessage = "Failed to delete group: \(error.localizedDescription)"
        }
    }

    func reorderGroups(_ groups: [HostGroup]) {
        do {
            try groupRepository.reorder(groups)
            fetchGroups()
        } catch {
            errorMessage = "Failed to reorder groups: \(error.localizedDescription)"
        }
    }
}
