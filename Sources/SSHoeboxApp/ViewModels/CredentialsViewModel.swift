import Foundation
import Combine
import SSHoeboxCore
import CryptoKit

@MainActor
class CredentialsViewModel: ObservableObject {
    @Published var credentials: [Credential] = []
    @Published var errorMessage: String?
    
    private let dbManager: DatabaseManager
    private let repository: CredentialRepository
    private let vaultKey: SymmetricKey
    private let hostId: String
    
    init(dbManager: DatabaseManager, vaultKey: SymmetricKey, hostId: String) {
        self.dbManager = dbManager
        self.vaultKey = vaultKey
        self.hostId = hostId
        self.repository = CredentialRepository(dbManager: dbManager)
        fetchCredentials()
    }
    
    func fetchCredentials() {
        do {
            credentials = try repository.getForHost(hostId: hostId)
            errorMessage = nil
        } catch {
            errorMessage = "Failed to fetch credentials: \(error.localizedDescription)"
        }
    }
    
    func addCredential(username: String, type: String, secret: String) {
        guard let secretData = secret.data(using: .utf8) else { return }
        
        // Encrypt username
        guard let encryptedUsername = try? CryptoManager.encryptString(username, using: vaultKey) else {
            errorMessage = "Failed to encrypt username."
            return
        }
        
        do {
            _ = try repository.createCredential(hostId: hostId, username: encryptedUsername, type: type, secret: secretData, vaultKey: vaultKey)
            fetchCredentials()
        } catch {
            errorMessage = "Failed to add credential: \(error.localizedDescription)"
        }
    }
    
    func updateCredential(id: String, username: String, type: String, secret: String) {
        guard let existingCredential = credentials.first(where: { $0.id == id }) else {
            errorMessage = "Credential not found"
            return
        }
        
        guard let secretData = secret.data(using: .utf8) else { return }
        
        // Encrypt username
        guard let encryptedUsername = try? CryptoManager.encryptString(username, using: vaultKey) else {
            errorMessage = "Failed to encrypt username."
            return
        }
        
        do {
            _ = try repository.updateCredential(
                id: id,
                hostId: hostId,
                username: encryptedUsername,
                type: type,
                secret: secretData,
                vaultKey: vaultKey,
                createdAt: existingCredential.createdAt
            )
            fetchCredentials()
        } catch {
            errorMessage = "Failed to update credential: \(error.localizedDescription)"
        }
    }

    
    func deleteCredential(at offsets: IndexSet) {
        offsets.forEach { index in
            let cred = credentials[index]
            deleteCredential(credential: cred)
        }
    }
    
    func deleteCredential(credential: Credential) {
        do {
            try repository.delete(credential)
            fetchCredentials()
        } catch {
            errorMessage = "Failed to delete credential: \(error.localizedDescription)"
        }
    }
    
    func decrypt(credential: Credential) -> String? {
        do {
            let data = try repository.decryptSecret(for: credential, vaultKey: vaultKey)
            return String(data: data, encoding: .utf8)
        } catch {
            errorMessage = "Decryption failed: \(error.localizedDescription)"
            return nil
        }
    }
}
