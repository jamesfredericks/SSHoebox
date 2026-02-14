import Foundation
import CryptoKit

public extension SavedHost {
    func decryptedName(using key: SymmetricKey) -> String {
        return (try? CryptoManager.decryptString(name, using: key)) ?? name
    }
    
    func decryptedHostname(using key: SymmetricKey) -> String {
        return (try? CryptoManager.decryptString(hostname, using: key)) ?? hostname
    }
    
    func decryptedUser(using key: SymmetricKey) -> String {
        return (try? CryptoManager.decryptString(user, using: key)) ?? user
    }
    
    mutating func encryptMetadata(using key: SymmetricKey) throws {
        // Only encrypt if not already encrypted? 
        // We assume the fields setting them are plaintext, so we overwrite with ciphertext.
        // Or we use this when saving new hosts.
        // Actually, better to have specific setters or handle it at callsites.
    }
}

public extension Credential {
    func decryptedUsername(using key: SymmetricKey) -> String {
        return (try? CryptoManager.decryptString(username, using: key)) ?? username
    }
}
