import Foundation
import Security

public struct KeychainManager {
    
    public static let serviceName = "com.sshoebox.app"
    
    /// Saves data to the keychain, replacing any existing value for `account`.
    /// Updates in place rather than deleting first, so a failed write never loses the old item.
    public static func save(_ data: Data, account: String) throws {
        // Use standard attribute instead of AccessControl for dev stability (ad-hoc signing changes)
        let itemQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            // Never migrates to another Mac through a keychain backup or sync.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        
        var status = SecItemUpdate(itemQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(itemQuery.merging(attributes) { $1 } as CFDictionary, nil)
        }
        
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
