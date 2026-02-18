import Foundation
import LocalAuthentication
import Security
import CryptoKit

/// Manages Touch ID / Face ID biometric authentication for vault unlock.
public struct BiometricAuthManager {
    
    private static let keychainAccount = "vault_biometric_key"
    private static let serviceName = "com.sshoebox.app"
    
    // MARK: - Availability
    
    /// Returns true if biometric authentication is available on this device.
    public static func isBiometricAvailable() -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Returns a human-readable name for the available biometric type.
    public static func biometricTypeName() -> String {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return "Biometrics"
        }
        switch context.biometryType {
        case .touchID: return "Touch ID"
        case .faceID:  return "Face ID"
        case .opticID: return "Optic ID"
        default:       return "Biometrics"
        }
    }
    
    /// Returns the appropriate SF Symbol name for the biometric type.
    public static func biometricSymbolName() -> String {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return "touchid"
        }
        switch context.biometryType {
        case .faceID:  return "faceid"
        default:       return "touchid"
        }
    }
    
    // MARK: - Enrollment
    
    /// Returns true if a biometric-protected vault key is currently enrolled.
    public static var isBiometricEnrolled: Bool {
        get { UserDefaults.standard.bool(forKey: "biometricUnlockEnabled") }
    }
    
    /// Saves the vault key to a biometric-protected Keychain item.
    /// This must be called after a successful password unlock to enroll biometrics.
    public static func enrollBiometric(vaultKey: SymmetricKey) throws {
        let keyData = vaultKey.withUnsafeBytes { Data($0) }
        
        // Create access control requiring biometric authentication
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else {
            throw BiometricError.accessControlCreationFailed
        }
        
        let query: [String: Any] = [
            kSecClass as String:               kSecClassGenericPassword,
            kSecAttrService as String:         serviceName,
            kSecAttrAccount as String:         keychainAccount,
            kSecValueData as String:           keyData,
            kSecAttrAccessControl as String:   access,
            kSecUseDataProtectionKeychain as String: true
        ]
        
        // Delete any existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: keychainAccount
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BiometricError.keychainError(status: status)
        }
        
        UserDefaults.standard.set(true, forKey: "biometricUnlockEnabled")
    }
    
    /// Retrieves the vault key using biometric authentication.
    /// Presents the Touch ID / Face ID prompt to the user.
    public static func unlockWithBiometrics() async throws -> SymmetricKey {
        let context = LAContext()
        context.localizedReason = "Unlock SSHoebox vault"
        
        // Evaluate biometric policy first
        do {
            try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Unlock SSHoebox vault"
            )
        } catch {
            throw BiometricError.authenticationFailed(reason: error.localizedDescription)
        }
        
        // Retrieve key from Keychain using the authenticated context
        let query: [String: Any] = [
            kSecClass as String:               kSecClassGenericPassword,
            kSecAttrService as String:         serviceName,
            kSecAttrAccount as String:         keychainAccount,
            kSecReturnData as String:          true,
            kSecMatchLimit as String:          kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess, let keyData = item as? Data else {
            throw BiometricError.keychainError(status: status)
        }
        
        return SymmetricKey(data: keyData)
    }
    
    /// Removes the biometric-protected vault key from Keychain and disables biometric unlock.
    public static func revokeBiometric() {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: keychainAccount
        ]
        SecItemDelete(query as CFDictionary)
        UserDefaults.standard.set(false, forKey: "biometricUnlockEnabled")
    }
}

// MARK: - Errors

public enum BiometricError: LocalizedError {
    case accessControlCreationFailed
    case authenticationFailed(reason: String)
    case keychainError(status: OSStatus)
    case notEnrolled
    
    public var errorDescription: String? {
        switch self {
        case .accessControlCreationFailed:
            return "Failed to create biometric access control."
        case .authenticationFailed(let reason):
            return "Biometric authentication failed: \(reason)"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .notEnrolled:
            return "Biometric unlock is not set up."
        }
    }
}
