import Foundation
import Combine
import SSHoeboxCore
import CryptoKit

@MainActor
class HostsViewModel: ObservableObject {
    @Published var hosts: [SavedHost] = []
    @Published var groups: [HostGroup] = []
    @Published var errorMessage: String?

    private let dbManager: DatabaseManager
    private let repository: HostRepository
    private let groupRepository: GroupRepository
    private let credentialRepository: CredentialRepository
    private let vaultKey: SymmetricKey

    init(dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.dbManager = dbManager
        self.repository = HostRepository(dbManager: dbManager)
        self.groupRepository = GroupRepository(dbManager: dbManager)
        self.credentialRepository = CredentialRepository(dbManager: dbManager)
        self.vaultKey = vaultKey
        fetchGroups()
        fetchHosts()
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
    var hostsGrouped: [(group: HostGroup?, hosts: [SavedHost])] {
        var result: [(group: HostGroup?, hosts: [SavedHost])] = []

        for group in groups {
            let members = hosts.filter { $0.groupId == group.id }
            if !members.isEmpty {
                result.append((group: group, hosts: members))
            }
        }

        let ungrouped = hosts.filter { $0.groupId == nil }
        if !ungrouped.isEmpty {
            result.append((group: nil, hosts: ungrouped))
        }

        return result
    }

    // MARK: - Host CRUD

    func addHost(name: String, hostname: String, port: Int, protocolType: String, user: String,
                 groupId: String? = nil,
                 credentialType: String = "none", credentialSecret: String = "") {
        guard let encryptedName = try? CryptoManager.encryptString(name, using: vaultKey),
              let encryptedHostname = try? CryptoManager.encryptString(hostname, using: vaultKey),
              let encryptedUser = try? CryptoManager.encryptString(user, using: vaultKey) else {
            errorMessage = "Failed to encrypt host data."
            return
        }

        let host = SavedHost(name: encryptedName, hostname: encryptedHostname,
                             port: port, protocolType: protocolType, user: encryptedUser,
                             groupId: groupId)
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
        } catch {
            errorMessage = "Failed to save host: \(error.localizedDescription)"
        }
    }

    func updateHost(id: String, name: String, hostname: String, port: Int,
                    protocolType: String, user: String, groupId: String? = nil) {
        guard let existingHost = hosts.first(where: { $0.id == id }) else {
            errorMessage = "Host not found"
            return
        }

        guard let encryptedName = try? CryptoManager.encryptString(name, using: vaultKey),
              let encryptedHostname = try? CryptoManager.encryptString(hostname, using: vaultKey),
              let encryptedUser = try? CryptoManager.encryptString(user, using: vaultKey) else {
            errorMessage = "Failed to encrypt host data."
            return
        }

        let updatedHost = SavedHost(
            id: id,
            name: encryptedName,
            hostname: encryptedHostname,
            port: port,
            protocolType: protocolType,
            user: encryptedUser,
            groupId: groupId,
            createdAt: existingHost.createdAt,
            updatedAt: Date()
        )

        do {
            try repository.save(updatedHost)
            fetchHosts()
        } catch {
            errorMessage = "Failed to update host: \(error.localizedDescription)"
        }
    }

    func deleteHost(at offsets: IndexSet) {
        offsets.forEach { index in
            let host = hosts[index]
            do {
                try repository.delete(host)
            } catch {
                errorMessage = "Failed to delete host: \(error.localizedDescription)"
            }
        }
        fetchHosts()
    }

    func deleteHost(_ host: SavedHost) {
        do {
            try repository.delete(host)
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
