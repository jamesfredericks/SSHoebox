import Foundation
import NIO
import NIOSSH
import SSHoeboxCore
import CryptoKit

// MARK: - SSH Agent Delegate
extension VaultViewModel: SSHAgentDelegate {
    @MainActor
    public func getIdentities() async -> [(key: Data, comment: String)] {
        guard isUnlocked, let dbManager = dbManager, let vaultKey = vaultKey else { return [] }
        
        do {
            let repo = CredentialRepository(dbManager: dbManager)
            // Filter for key-based credentials
            let allCreds = try repo.getAll()
            let keyCreds = allCreds.filter { $0.type == "key" }
            
            var identities: [(Data, String)] = []
            
            for cred in keyCreds {
                // Decrypt private key
                if let keyData = try? repo.decryptSecret(for: cred, vaultKey: vaultKey),
                   let _ = String(data: keyData, encoding: .utf8) {
                    
                    // TODO: Parse key using NIOSSH
                    // Currently NIOSSHPrivateKey(opensshPrivateKey:) is missing in dependency.
                    // We skip parsing to ensure build stability.
                    print("Agent: Parsing key for \(cred.username) skipped (missing dependency capability)")
                    
                    /*
                    if let key = try? NIOSSHPrivateKey(opensshPrivateKey: keyString),
                       case .ed25519(let edKey) = key {
                        
                        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
                        let pubKey = NIOSSHPublicKey(edKey.publicKey)
                        pubKey.write(to: &buffer)
                        
                        if let pubKeyBytes = buffer.readBytes(length: buffer.readableBytes) {
                            let comment = cred.username
                            identities.append((Data(pubKeyBytes), comment))
                        }
                    }
                    */
                }
            }
            return identities
        } catch {
            print("Agent fetch error: \(error)")
            return []
        }
    }
    
    @MainActor
    public func sign(key: Data, data: Data, flags: UInt32) async throws -> Data {
        guard isUnlocked, let _ = dbManager, let _ = vaultKey else {
            throw SSHAgentError.invalidMessage
        }
        
        // TODO: Implement signing once key parsing is fixed
        throw SSHAgentError.invalidMessage
    }
}
