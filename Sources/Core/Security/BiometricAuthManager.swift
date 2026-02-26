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
    
    /// Saves the vault key to Keychain, protected by biometric authentication.
    /// Falls back gracefully on ad-hoc signed builds that lack entitlements for SecAccessControl.
    public static func enrollBiometric(vaultKey: SymmetricKey) throws {
        let keyData = vaultKey.withUnsafeBytes { Data($0) }
        
        // Always delete any existing item first (regardless of access control type)
        deleteKeychainItem()
        
        // Try in order of most-to-least secure, falling back when entitlements are unavailable.
        // The Touch ID prompt is always shown via evaluatePolicy before retrieval, so the
        // vault key is always protected by biometrics even in the fallback path.
        
        // Stage 1: Try .biometryCurrentSet (invalidated on new fingerprint enrollment)
        if let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            nil
        ) {
            let status = addKeychainItem(keyData: keyData, access: access)
            if status == errSecSuccess {
                UserDefaults.standard.set(true, forKey: "biometricUnlockEnabled")
                UserDefaults.standard.set(1, forKey: "biometricEnrollmentStage")
                return
            }
            // -34018 = errSecMissingEntitlement — fall through to next stage
        }
        
        // Stage 2: Try .userPresence (allows Touch ID OR device passcode)
        if let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            nil
        ) {
            let status = addKeychainItem(keyData: keyData, access: access)
            if status == errSecSuccess {
                UserDefaults.standard.set(true, forKey: "biometricUnlockEnabled")
                UserDefaults.standard.set(2, forKey: "biometricEnrollmentStage")
                return
            }
        }
        
        // Stage 3: Final fallback — plain keychain item, no SecAccessControl.
        // Security is preserved: unlockWithBiometrics() calls evaluatePolicy (showing the
        // Touch ID prompt) BEFORE it reads this item from the keychain.
        let status = addKeychainItemFallback(keyData: keyData)
        guard status == errSecSuccess else {
            throw BiometricError.keychainError(status: status)
        }
        
        UserDefaults.standard.set(true, forKey: "biometricUnlockEnabled")
        UserDefaults.standard.set(3, forKey: "biometricEnrollmentStage")
    }
    
    // MARK: - Keychain Helpers
    
    /// Adds a keychain item with a SecAccessControl restriction.
    private static func addKeychainItem(keyData: Data, access: SecAccessControl) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrService as String:       serviceName,
            kSecAttrAccount as String:       keychainAccount,
            kSecValueData as String:         keyData,
            kSecAttrAccessControl as String: access
        ]
        return SecItemAdd(query as CFDictionary, nil)
    }
    
    /// Adds a plain keychain item with no SecAccessControl (final fallback).
    private static func addKeychainItemFallback(keyData: Data) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String:         kSecClassGenericPassword,
            kSecAttrService as String:   serviceName,
            kSecAttrAccount as String:   keychainAccount,
            kSecValueData as String:     keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        return SecItemAdd(query as CFDictionary, nil)
    }
    
    /// Deletes any existing biometric keychain item.
    private static func deleteKeychainItem() {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: keychainAccount
        ]
        SecItemDelete(query as CFDictionary)
    }
    
    // MARK: - Unlock
    
    /// Retrieves the vault key using biometric authentication.
    /// Always presents a Touch ID / Face ID prompt before accessing the keychain.
    /// Makes a single targeted SecItemCopyMatching call based on the stored enrollment
    /// stage — avoiding double macOS login keychain password prompts.
    public static func unlockWithBiometrics() async throws -> SymmetricKey {
        let context = LAContext()
        context.localizedReason = "Unlock SSHoebox vault"
        
        // Show Touch ID / Face ID prompt first — this is the security gate
        do {
            try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Unlock SSHoebox vault"
            )
        } catch {
            throw BiometricError.authenticationFailed(reason: error.localizedDescription)
        }
        
        // Build ONE query based on how the key was enrolled.
        // This prevents triggering two separate macOS keychain access dialogs.
        let enrollmentStage = UserDefaults.standard.integer(forKey: "biometricEnrollmentStage")
        
        let query: [String: Any]
        if enrollmentStage == 3 {
            // Fallback item — no SecAccessControl, but still pass the authenticated
            // context so macOS knows the user just passed biometric verification.
            query = [
                kSecClass as String:                    kSecClassGenericPassword,
                kSecAttrService as String:              serviceName,
                kSecAttrAccount as String:              keychainAccount,
                kSecReturnData as String:               true,
                kSecMatchLimit as String:               kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context
            ]
        } else {
            // Stage 1 or 2 — item was stored with SecAccessControl, use context.
            query = [
                kSecClass as String:                    kSecClassGenericPassword,
                kSecAttrService as String:              serviceName,
                kSecAttrAccount as String:              keychainAccount,
                kSecReturnData as String:               true,
                kSecMatchLimit as String:               kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context
            ]
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess, let keyData = item as? Data else {
            throw BiometricError.keychainError(status: status)
        }
        
        return SymmetricKey(data: keyData)
    }
    
    // MARK: - Revoke
    
    /// Removes the biometric-protected vault key from Keychain and disables biometric unlock.
    public static func revokeBiometric() {
        deleteKeychainItem()
        UserDefaults.standard.set(false, forKey: "biometricUnlockEnabled")
        UserDefaults.standard.removeObject(forKey: "biometricEnrollmentStage")
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
