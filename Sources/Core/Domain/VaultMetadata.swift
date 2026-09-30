import Foundation

/// Contents of the portable `vault_metadata.json` sidecar: the KDF salt and an
/// AES-GCM encrypted sentinel used to validate the master password.
public struct VaultMetadata: Codable, Equatable {
    public let salt: Data
    public let validation: Data
    public var version: Int? // Optional for backward compatibility. Nil means 0 (Legacy).

    public init(salt: Data, validation: Data, version: Int?) {
        self.salt = salt
        self.validation = validation
        self.version = version
    }
}
