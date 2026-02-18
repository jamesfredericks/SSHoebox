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
                   let keyString = String(data: keyData, encoding: .utf8) {
                    
                    // Parse key using NIOSSH
                    // Only supporting Ed25519 for now, others can be added
                    if let key = try? NIOSSHPrivateKey(opensshPrivateKey: keyString),
                       case .ed25519(let edKey) = key {
                        
                        // Serialize public key as SSH blob
                        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
                        let pubKey = NIOSSHPublicKey(edKey.publicKey)
                        pubKey.write(to: &buffer)
                        
                        if let pubKeyBytes = buffer.readBytes(length: buffer.readableBytes) {
                            let comment = cred.label // Use label as comment
                            identities.append((Data(pubKeyBytes), comment))
                        }
                    }
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
        guard isUnlocked, let dbManager = dbManager, let vaultKey = vaultKey else {
            throw SSHAgentError.invalidMessage
        }
        
        let repo = CredentialRepository(dbManager: dbManager)
        let allCreds = try repo.getAll().filter { $0.type == "key" }
        
        for cred in allCreds {
            if let keyData = try? repo.decryptSecret(for: cred, vaultKey: vaultKey),
               let keyString = String(data: keyData, encoding: .utf8),
               let privKey = try? NIOSSHPrivateKey(opensshPrivateKey: keyString) {
                
                // Check if public key matches
                var buffer = ByteBufferAllocator().buffer(capacity: 1024)
                privKey.publicKey.write(to: &buffer)
                if let pubKeyBytes = buffer.readBytes(length: buffer.readableBytes),
                   Data(pubKeyBytes) == key {
                    
                    // Found matching key! Sign the data.
                    let signature = try privKey.sign(data: data)
                    
                    // Serialize signature as SSH blob
                    // string algorithm
                    // string signature_bytes
                    var sigBuffer = ByteBufferAllocator().buffer(capacity: 1024)
                    signature.write(to: &sigBuffer)
                    
                    // The agent protocol expects the signature blob itself
                    if let sigBytes = sigBuffer.readBytes(length: sigBuffer.readableBytes) {
                        return Data(sigBytes)
                    }
                }
            }
        }
        
        throw SSHAgentError.invalidMessage // Key not found
    }
}
