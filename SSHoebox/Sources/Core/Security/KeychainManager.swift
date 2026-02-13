import Foundation
import Security

public struct KeychainManager {
    
    public static let serviceName = "com.sshoebox.app"
    
    /// Saves data to the keychain.
    public static func save(_ data: Data, account: String) throws {
        // Use standard attribute instead of AccessControl for dev stability (ad-hoc signing changes)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        // Delete existing item if any
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status != errSecSuccess {
            throw SecurityError.keychainError(status: status)
        }
    }
    
    /// Reads data from the keychain.
    public static func read(account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecItemNotFound {
            throw SecurityError.itemNotFound
        } else if status != errSecSuccess {
            throw SecurityError.keychainError(status: status)
        }
        
        guard let data = item as? Data else {
            throw SecurityError.keychainError(status: -1) // Unknown error
        }
        
        return data
    }
    
    /// Deletes data from the keychain.
    public static func delete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        if status != errSecSuccess && status != errSecItemNotFound {
            throw SecurityError.keychainError(status: status)
        }
    }
}
