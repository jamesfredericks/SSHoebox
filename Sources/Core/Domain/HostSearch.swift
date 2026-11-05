import Foundation
import CryptoKit

/// Matching hosts against a search: every word must appear in the name, hostname, user or
/// a tag. A word starting with `#` only matches tags (`#prod web`).
public enum HostSearch {
    public static func matches(_ host: SavedHost, query: String, vaultKey: SymmetricKey) -> Bool {
        let words = query.lowercased().split(whereSeparator: \.isWhitespace).map(String.init)
        guard !words.isEmpty else { return true }
        let tags = host.decryptedOptions(using: vaultKey).tags.map { $0.lowercased() }
        let fields = [host.decryptedName(using: vaultKey), host.decryptedHostname(using: vaultKey),
                      host.decryptedUser(using: vaultKey)].map { $0.lowercased() } + tags
        return words.allSatisfy { word in
            if word.hasPrefix("#"), word.count > 1 {
                let tag = word.dropFirst()
                return tags.contains { $0.hasPrefix(tag) }
            }
            return fields.contains { $0.contains(word) }
        }
    }

    /// How well a host matches, for ordering Quick Connect results: name prefix first, then
    /// name contains, then anything else; more recently connected hosts first within each.
    public static func score(_ host: SavedHost, query: String, vaultKey: SymmetricKey) -> Int {
        let q = query.lowercased().trimmingCharacters(in: .whitespaces)
        let name = host.decryptedName(using: vaultKey).lowercased()
        if q.isEmpty { return 0 }
        if name.hasPrefix(q) { return 3 }
        if name.contains(q) { return 2 }
        if host.decryptedHostname(using: vaultKey).lowercased().hasPrefix(q) { return 1 }
        return 0
    }
}
