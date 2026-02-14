import Foundation
import Combine
import SSHoeboxCore
import CryptoKit

@MainActor
class HostsViewModel: ObservableObject {
    @Published var hosts: [SavedHost] = []
    @Published var errorMessage: String?
    
    private let dbManager: DatabaseManager
    private let repository: HostRepository
    private let credentialRepository: CredentialRepository
    private let vaultKey: SymmetricKey
    
    init(dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.dbManager = dbManager
        self.repository = HostRepository(dbManager: dbManager)
        self.credentialRepository = CredentialRepository(dbManager: dbManager)
        self.vaultKey = vaultKey
        fetchHosts()
    }
    
    func fetchHosts() {
        do {
            hosts = try repository.getAll()
            errorMessage = nil
        } catch {
            errorMessage = "Failed to fetch hosts: \(error.localizedDescription)"
        }
    }
    
    func addHost(name: String, hostname: String, port: Int, protocolType: String, user: String, credentialType: String = "none", credentialSecret: String = "") {
        // Encrypt metadata before saving
        guard let encryptedName = try? CryptoManager.encryptString(name, using: vaultKey),
              let encryptedHostname = try? CryptoManager.encryptString(hostname, using: vaultKey),
              let encryptedUser = try? CryptoManager.encryptString(user, using: vaultKey) else {
            errorMessage = "Failed to encrypt host data."
            return
        }
        
        let host = SavedHost(name: encryptedName, hostname: encryptedHostname, port: port, protocolType: protocolType, user: encryptedUser)
        do {
            try repository.save(host)
            
            // Add credential if provided
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
}
