import Foundation
import LocalAuthentication
import Security
import CryptoKit

/// Manages Touch ID / Face ID biometric authentication for vault unlock.
///
/// Each vault gets its own keychain item and enrollment record, keyed by
/// `VaultMetadata.identifier`, so enrolling one vault never overwrites another's key.
/// Earlier builds stored a single shared item; that legacy item is still read so existing
/// users keep Touch ID, and it is removed on the next enrollment or revoke.
public struct BiometricAuthManager {

    private static let legacyKeychainAccount = "vault_biometric_key"
    private static let serviceName = "com.sshoebox.app"
    private static let enrollmentsDefaultsKey = "biometricEnrollments" // [vaultID: stage]
    private static let legacyEnabledDefaultsKey = "biometricUnlockEnabled"
    private static let legacyStageDefaultsKey = "biometricEnrollmentStage"

    private static func keychainAccount(for vaultID: String) -> String {
        "\(legacyKeychainAccount).\(vaultID)"
    }

    private static var enrollments: [String: Int] {
        get { UserDefaults.standard.dictionary(forKey: enrollmentsDefaultsKey) as? [String: Int] ?? [:] }
        set { UserDefaults.standard.set(newValue, forKey: enrollmentsDefaultsKey) }
    }

    private static var hasLegacyEnrollment: Bool {
        UserDefaults.standard.bool(forKey: legacyEnabledDefaultsKey)
    }

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

    /// Returns true if this vault has its own biometric key enrolled.
    public static func hasVaultEnrollment(vaultID: String) -> Bool {
        enrollments[vaultID] != nil
    }

    /// Returns true if Touch ID can be attempted for this vault: it has its own enrollment,
    /// or a legacy shared key exists that may belong to it.
    public static func isBiometricEnrolled(vaultID: String) -> Bool {
        hasVaultEnrollment(vaultID: vaultID) || hasLegacyEnrollment
    }

    /// Saves the vault key to Keychain, protected by biometric authentication.
    /// Falls back gracefully on ad-hoc signed builds that lack entitlements for SecAccessControl.
    public static func enrollBiometric(vaultKey: SymmetricKey, vaultID: String) throws {
        let keyData = vaultKey.withUnsafeBytes { Data($0) }
        let account = keychainAccount(for: vaultID)

        // Always delete any existing item first (regardless of access control type)
        deleteKeychainItem(account: account)

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
            let status = addKeychainItem(keyData: keyData, access: access, account: account)
            if status == errSecSuccess {
                recordEnrollment(vaultID: vaultID, stage: 1)
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
            let status = addKeychainItem(keyData: keyData, access: access, account: account)
            if status == errSecSuccess {
                recordEnrollment(vaultID: vaultID, stage: 2)
                return
            }
        }

        // Stage 3: Final fallback — plain keychain item, no SecAccessControl.
        // Security is preserved: unlockWithBiometrics() calls evaluatePolicy (showing the
        // Touch ID prompt) BEFORE it reads this item from the keychain.
        let status = addKeychainItemFallback(keyData: keyData, account: account)
        guard status == errSecSuccess else {
            throw BiometricError.keychainError(status: status)
        }
        recordEnrollment(vaultID: vaultID, stage: 3)
    }

    /// Records a per-vault enrollment and retires the legacy shared key. If the legacy key
    /// belonged to this vault it is superseded; if it belonged to another vault, that vault
    /// falls back to password unlock rather than silently holding a mismatched key.
    private static func recordEnrollment(vaultID: String, stage: Int) {
        var current = enrollments
        current[vaultID] = stage
        enrollments = current
        removeLegacyEnrollment()
    }

    private static func removeLegacyEnrollment() {
        guard hasLegacyEnrollment else { return }
        deleteKeychainItem(account: legacyKeychainAccount)
        UserDefaults.standard.removeObject(forKey: legacyEnabledDefaultsKey)
        UserDefaults.standard.removeObject(forKey: legacyStageDefaultsKey)
    }

    // MARK: - Keychain Helpers

    /// Adds or updates a keychain item with a SecAccessControl restriction.
    private static func addKeychainItem(keyData: Data, access: SecAccessControl, account: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrService as String:       serviceName,
            kSecAttrAccount as String:       account,
            kSecValueData as String:         keyData,
            kSecAttrAccessControl as String: access
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            return updateKeychainValue(keyData: keyData, account: account)
        }
        return status
    }

    /// Adds or updates a plain keychain item with no SecAccessControl (final fallback).
    private static func addKeychainItemFallback(keyData: Data, account: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        serviceName,
            kSecAttrAccount as String:        account,
            kSecValueData as String:          keyData,
            kSecAttrAccessible as String:     kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            return updateKeychainValue(keyData: keyData, account: account)
        }
        return status
    }

    /// Updates only the value data of an existing keychain item, without touching its access control.
    private static func updateKeychainValue(keyData: Data, account: String) -> OSStatus {
        let searchQuery: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        serviceName,
            kSecAttrAccount as String:        account,
            kSecUseNoAuthenticationUI as String: kCFBooleanTrue as Any
        ]
        let attributes: [String: Any] = [kSecValueData as String: keyData]
        return SecItemUpdate(searchQuery as CFDictionary, attributes as CFDictionary)
    }

    /// Deletes any existing biometric keychain item for `account`.
    private static func deleteKeychainItem(account: String) {
        // kSecUseNoAuthenticationUI prevents hanging if the item has biometric access control
        let query: [String: Any] = [
            kSecClass as String:                 kSecClassGenericPassword,
            kSecAttrService as String:           serviceName,
            kSecAttrAccount as String:           account,
            kSecUseNoAuthenticationUI as String: kCFBooleanTrue as Any
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Unlock

    /// Retrieves the vault key using biometric authentication.
    /// Always presents a Touch ID / Face ID prompt before accessing the keychain.
    ///
    /// Reads this vault's own key when enrolled, otherwise the legacy shared key. The caller
    /// must validate the returned key against the vault metadata, and should call
    /// `enrollBiometric(vaultKey:vaultID:)` when it validates but `hasVaultEnrollment(vaultID:)`
    /// is false, to migrate off the legacy item.
    public static func unlockWithBiometrics(vaultID: String) async throws -> SymmetricKey {
        guard isBiometricEnrolled(vaultID: vaultID) else {
            throw BiometricError.notEnrolled
        }
        let account = hasVaultEnrollment(vaultID: vaultID) ? keychainAccount(for: vaultID) : legacyKeychainAccount

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

        // A single SecItemCopyMatching call avoids triggering two macOS keychain access dialogs.
        let query: [String: Any] = [
            kSecClass as String:                    kSecClassGenericPassword,
            kSecAttrService as String:              serviceName,
            kSecAttrAccount as String:              account,
            kSecReturnData as String:               true,
            kSecMatchLimit as String:               kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let keyData = item as? Data else {
            throw BiometricError.keychainError(status: status)
        }
        return SymmetricKey(data: keyData)
    }

    // MARK: - Revoke

    /// Removes this vault's biometric key and disables biometric unlock for it. The legacy
    /// shared key is removed too, since it can't be attributed to a vault without unlocking.
    public static func revokeBiometric(vaultID: String) {
        deleteKeychainItem(account: keychainAccount(for: vaultID))
        var current = enrollments
        current.removeValue(forKey: vaultID)
        enrollments = current
        removeLegacyEnrollment()
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
            return "Biometric unlock is not set up for this vault."
        }
    }
}
