import Foundation
import NIO
import SSHoeboxCore

// MARK: - SSH Agent Delegate

extension VaultViewModel: SSHAgentDelegate {

    /// Returns all SSH key identities currently in the vault.
    ///
    /// Each identity is a pair of:
    /// - `key`: SSH wire-format public key blob (`uint32(algo_len) + algo + key_data`)
    /// - `comment`: The credential's username, used as the key comment
    ///
    /// Only credentials with `type == "key"` are considered.
    @MainActor
    public func getIdentities() async -> [(key: Data, comment: String)] {
        guard isUnlocked, let dbManager = dbManager, let vaultKey = vaultKey else {
            return []
        }

        do {
            let repo = CredentialRepository(dbManager: dbManager)
            let keyCreds = try repo.getAll().filter { $0.type == "key" }

            var identities: [(Data, String)] = []

            for cred in keyCreds {
                guard
                    let keyData = try? repo.decryptSecret(for: cred, vaultKey: vaultKey),
                    let pem = String(data: keyData, encoding: .utf8),
                    let blob = try? SSHKeyParser.publicKeyBlob(fromPEM: pem)
                else {
                    print("SSH Agent: skipping \(cred.username) — could not parse key")
                    continue
                }

                identities.append((blob, cred.username))
                print("SSH Agent: registered key for \(cred.username)")
            }

            return identities

        } catch {
            print("SSH Agent: error fetching identities — \(error)")
            return []
        }
    }

    /// Signs `data` using the vault key identified by the given public key blob.
    ///
    /// The agent compares `key` against every stored SSH credential's public key blob
    /// to find the matching private key, then produces an SSH agent signature blob:
    /// `uint32(algo_len) + algo_string + uint32(sig_len) + signature_bytes`
    @MainActor
    public func sign(key: Data, data: Data, flags: UInt32) async throws -> Data {
        guard isUnlocked, let dbManager = dbManager, let vaultKey = vaultKey else {
            throw SSHAgentError.invalidMessage
        }

        let repo = CredentialRepository(dbManager: dbManager)
        let keyCreds = try repo.getAll().filter { $0.type == "key" }

        for cred in keyCreds {
            guard
                let keyData = try? repo.decryptSecret(for: cred, vaultKey: vaultKey),
                let pem = String(data: keyData, encoding: .utf8)
            else { continue }

            // Match the requested key blob against this credential's public key
            guard SSHKeyParser.publicKeyBlobMatches(blob: key, pem: pem) else { continue }

            // Found the matching key — sign and return
            print("SSH Agent: signing with key for \(cred.username)")
            return try SSHKeyParser.sign(pem: pem, data: data)
        }

        // No matching key found
        print("SSH Agent: no matching key found for sign request")
        throw SSHAgentError.invalidMessage
    }
}
