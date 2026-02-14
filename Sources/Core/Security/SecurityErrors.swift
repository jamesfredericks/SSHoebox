import Foundation

public enum SecurityError: Error, LocalizedError {
    case encryptionFailed
    case decryptionFailed
    case keyDerivationFailed
    case invalidKey
    case keychainError(status: OSStatus)
    case itemNotFound
    case duplicateItem
    case rngFailed
    
    public var errorDescription: String? {
        switch self {
        case .encryptionFailed:
            return "Encryption operation failed."
        case .decryptionFailed:
            return "Decryption operation failed."
        case .keyDerivationFailed:
            return "Key derivation failed."
        case .invalidKey:
            return "The provided key is invalid."
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .itemNotFound:
            return "Item not found in Keychain."
        case .duplicateItem:
            return "Item already exists in Keychain."
        case .rngFailed:
            return "Random number generation failed."
        }
    }
}
