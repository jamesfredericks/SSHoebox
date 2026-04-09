import Foundation

/// Parses an OpenSSH client config file (~/.ssh/config) into structured host entries.
public struct SSHConfigParser {

    public struct ConfigHost {
        public let alias: String          // The "Host" pattern (used as display name)
        public let hostname: String       // Resolved HostName (or alias if not specified)
        public let port: Int              // Default 22
        public let user: String           // User directive (may be empty)
        public let identityFile: String?  // First IdentityFile path (may be empty)
    }

    /// Parse an SSH config file at the given path. Silently skips wildcard (`*`, `?`) aliases.
    public static func parse(contentsOf url: URL) throws -> [ConfigHost] {
        let content = try String(contentsOf: url, encoding: .utf8)
        return parse(string: content)
    }

    /// Parse SSH config from a string.
    public static func parse(string: String) -> [ConfigHost] {
        var results: [ConfigHost] = []

        var currentAlias: String? = nil
        var hostname: String? = nil
        var port: Int = 22
        var user: String = ""
        var identityFile: String? = nil

        func flush() {
            guard let alias = currentAlias, !alias.isEmpty,
                  !alias.contains("*"), !alias.contains("?") else { return }
            let resolvedHostname = hostname ?? alias
            guard !resolvedHostname.isEmpty else { return }
            results.append(ConfigHost(
                alias: alias,
                hostname: resolvedHostname,
                port: port,
                user: user,
                identityFile: identityFile
            ))
        }

        for rawLine in string.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            // Skip comments and empty lines
            if line.isEmpty || line.hasPrefix("#") { continue }

            let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 2 else { continue }

            let key = parts[0].lowercased()
            let value = parts.dropFirst().joined(separator: " ")

            switch key {
            case "host":
                flush()
                currentAlias = value
                hostname = nil
                port = 22
                user = ""
                identityFile = nil
            case "hostname":
                hostname = value
            case "port":
                port = Int(value) ?? 22
            case "user":
                user = value
            case "identityfile":
                if identityFile == nil {
                    identityFile = (value as NSString).expandingTildeInPath
                }
            default:
                break
            }
        }

        flush()
        return results
    }
}
