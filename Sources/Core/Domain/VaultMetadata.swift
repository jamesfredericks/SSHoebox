import Foundation
import CryptoKit

/// Contents of the portable `vault_metadata.json` sidecar: the KDF salt and an
/// AES-GCM encrypted sentinel used to validate the master password.
public struct VaultMetadata: Codable, Equatable {
    public let salt: Data
    public let validation: Data
    public var version: Int? // Optional for backward compatibility. Nil means 0 (Legacy).

    /// Stable, non-secret identifier for this vault (derived from its salt), used to
    /// scope per-vault state such as the biometric keychain item.
    public var identifier: String {
        SHA256.hash(data: salt).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    public init(salt: Data, validation: Data, version: Int?) {
        self.salt = salt
        self.validation = validation
        self.version = version
    }
}
