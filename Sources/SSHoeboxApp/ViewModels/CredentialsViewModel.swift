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
    
    func addCredential(username: String, type: String, secret: String, isInteractive: Bool = false) {
        guard let secretData = secret.data(using: .utf8) else { return }
        
        do {
            _ = try repository.createCredential(hostId: hostId, username: username, type: type, secret: secretData, vaultKey: vaultKey, isInteractive: isInteractive)
            fetchCredentials()
        } catch {
            errorMessage = "Failed to add credential: \(error.localizedDescription)"
        }
    }
    
    func updateCredential(id: String, username: String, type: String, secret: String, isInteractive: Bool) {
        guard let existingCredential = credentials.first(where: { $0.id == id }) else {
            errorMessage = "Credential not found"
            return
        }

        guard let secretData = secret.data(using: .utf8) else { return }

        // Archive the old secret in history before overwriting (only if it actually changed).
        // An agent credential holds a key reference, not a secret, so there's nothing to archive.
        if existingCredential.type != SSHAgentKeyReference.credentialType,
           let oldSecret = try? repository.decryptSecret(for: existingCredential, vaultKey: vaultKey),
           oldSecret != secretData {
            let historyRepo = PasswordHistoryRepository(dbManager: dbManager)
            try? historyRepo.add(credentialId: id, oldSecret: oldSecret, vaultKey: vaultKey)
        }

        do {
            _ = try repository.updateCredential(
                id: id,
                hostId: hostId,
                username: username,
                type: type,
                secret: secretData,
                vaultKey: vaultKey,
                isInteractive: isInteractive,
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
    
    /// The agent and key an `agent` credential refers to.
    func agentKey(for credential: Credential) -> SSHAgentKeyReference? {
        guard credential.type == SSHAgentKeyReference.credentialType else { return nil }
        do {
            return try SSHAgentKeyReference.decode(repository.decryptSecret(for: credential, vaultKey: vaultKey))
        } catch {
            errorMessage = "Could not read the SSH agent key: \(error.localizedDescription)"
            return nil
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
