import Foundation

/// A host + login parsed from a password-manager export, ready to be saved.
public struct CredentialImportEntry: Identifiable {
    public let id = UUID()
    public let name: String
    public let hostname: String
    public let port: Int
    public let username: String
    /// Exactly as it appeared in the export; never trimmed or unescaped further.
    public let password: String
    public let notes: String

    public init(name: String, hostname: String, port: Int, username: String, password: String, notes: String) {
        self.name = name
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.notes = notes
    }
}

/// Parses CSV (SSHoebox, Bitwarden, 1Password, LastPass, Chrome, Firefox, KeePassXC) and
/// Bitwarden JSON exports into `CredentialImportEntry` values.
public enum CredentialImporter {

    public enum ImportError: LocalizedError, Equatable {
        case invalidFormat
        case encryptedExport
        case missingHostColumn

        public var errorDescription: String? {
            switch self {
            case .invalidFormat:
                return "The file is not a valid Bitwarden JSON export."
            case .encryptedExport:
                return "This Bitwarden export is encrypted. Export again using the unencrypted .json format."
            case .missingHostColumn:
                return "The CSV header has no hostname or URL column."
            }
        }
    }

    /// Picks JSON or CSV by file extension, falling back to sniffing for a leading `{`.
    public static func parse(_ content: String, fileExtension: String) throws -> [CredentialImportEntry] {
        let body = content.hasPrefix("\u{FEFF}") ? String(content.dropFirst()) : content
        let looksLikeJSON = body.first(where: { !$0.isWhitespace }) == "{"
        if fileExtension.lowercased() == "json" || looksLikeJSON {
            return try parseBitwardenJSON(Data(body.utf8))
        }
        return try parseCSV(body)
    }

    // MARK: - CSV

    private enum Field: CaseIterable {
        case name, hostname, url, port, username, password, notes

        /// Normalised header names (lowercased, spaces and underscores removed).
        var headerNames: Set<String> {
            switch self {
            case .name:     return ["name", "title", "account", "accountname"]
            case .hostname: return ["hostname", "host", "hostaddress", "server", "address", "ip", "ipaddress"]
            case .url:      return ["url", "uri", "loginuri", "website", "loginurl", "urls", "weburl"]
            case .port:     return ["port"]
            case .username: return ["username", "user", "loginusername", "login", "loginname"]
            case .password: return ["password", "loginpassword", "pass"]
            case .notes:    return ["notes", "note", "extra", "comments", "comment"]
            }
        }
    }

    private static func normalizeHeader(_ header: String) -> String {
        header.lowercased().filter { !$0.isWhitespace && $0 != "_" && $0 != "\u{FEFF}" }
    }

    /// Parses a CSV export. Columns are mapped by header name; a file whose first row has no
    /// recognised header is read positionally as `name, hostname, port, username, password, notes`.
    public static func parseCSV(_ content: String) throws -> [CredentialImportEntry] {
        let rows = try CSVParser.parse(content)
        guard let header = rows.first else { return [] }

        var columns: [Field: Int] = [:]
        for (index, title) in header.enumerated() {
            let key = normalizeHeader(title)
            if let field = Field.allCases.first(where: { $0.headerNames.contains(key) }), columns[field] == nil {
                columns[field] = index
            }
        }

        let dataRows: ArraySlice<[String]>
        if columns.isEmpty {
            // No header: legacy SSHoebox positional layout
            columns = [.name: 0, .hostname: 1, .port: 2, .username: 3, .password: 4, .notes: 5]
            dataRows = rows[...]
        } else {
            guard columns[.hostname] != nil || columns[.url] != nil else { throw ImportError.missingHostColumn }
            dataRows = rows.dropFirst()
        }

        return dataRows.compactMap { row in
            func value(_ field: Field) -> String {
                guard let index = columns[field], index < row.count else { return "" }
                return row[index]
            }
            // Skip blank lines
            if row.allSatisfy({ $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) { return nil }

            let urlValue = value(.url).trimmingCharacters(in: .whitespacesAndNewlines)
            if urlValue.lowercased() == "http://sn" { return nil } // LastPass secure note

            guard let address = HostAddress.parseFirst(value(.hostname)) ?? HostAddress.parseFirst(urlValue) else {
                return nil
            }

            let portText = value(.port).trimmingCharacters(in: .whitespaces)
            let port = HostAddress.validPort(portText) ?? address.port ?? 22
            var username = value(.username).trimmingCharacters(in: .whitespacesAndNewlines)
            if username.isEmpty, let urlUser = address.user { username = urlUser }
            let name = value(.name).trimmingCharacters(in: .whitespacesAndNewlines)

            return CredentialImportEntry(
                name: name.isEmpty ? address.host : name,
                hostname: address.host,
                port: port,
                username: username,
                password: value(.password),
                notes: value(.notes)
            )
        }
    }

    // MARK: - Bitwarden JSON

    /// Parses an unencrypted Bitwarden JSON export, keeping Login items that have a URI.
    public static func parseBitwardenJSON(_ data: Data) throws -> [CredentialImportEntry] {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw ImportError.invalidFormat
        }
        if root["encrypted"] as? Bool == true { throw ImportError.encryptedExport }
        guard let items = root["items"] as? [[String: Any]] else { throw ImportError.invalidFormat }

        return items.compactMap { item in
            guard (item["type"] as? NSNumber)?.intValue == 1,  // 1 = Login
                  let login = item["login"] as? [String: Any] else { return nil }

            let uris = (login["uris"] as? [[String: Any]])?.compactMap { $0["uri"] as? String } ?? []
            guard let address = uris.lazy.compactMap(HostAddress.parseFirst).first else { return nil }

            var username = (login["username"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if username.isEmpty, let urlUser = address.user { username = urlUser }
            let name = (item["name"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)

            return CredentialImportEntry(
                name: name.isEmpty ? address.host : name,
                hostname: address.host,
                port: address.port ?? 22,
                username: username,
                password: login["password"] as? String ?? "",
                notes: item["notes"] as? String ?? ""
            )
        }
    }
}

/// Extracts host, port and user from the loose address formats found in exports:
/// `host`, `host:port`, `user@host`, `[v6]:port`, bare IPv6, and URLs such as
/// `ssh://user@host:2222` or `https://host/login`.
public struct HostAddress: Equatable {
    public let host: String
    public let port: Int?
    public let user: String?

    public init(host: String, port: Int?, user: String?) {
        self.host = host
        self.port = port
        self.user = user
    }

    /// Parses the first usable address in a field that may hold several, separated by
    /// commas or newlines (Bitwarden CSV joins multiple URIs with commas).
    public static func parseFirst(_ field: String) -> HostAddress? {
        field.split(whereSeparator: { $0 == "," || $0.isNewline })
            .lazy
            .compactMap { parse(String($0)) }
            .first
    }

    public static func parse(_ raw: String) -> HostAddress? {
        var rest = Substring(raw.trimmingCharacters(in: .whitespacesAndNewlines))

        // Scheme
        if let range = rest.range(of: "://") {
            let scheme = rest[..<range.lowerBound]
            if let first = scheme.first, first.isLetter,
               scheme.allSatisfy({ $0.isLetter || $0.isNumber || "+-.".contains($0) }) {
                rest = rest[range.upperBound...]
            }
        }
        // Authority ends at the path, query or fragment
        if let end = rest.firstIndex(where: { "/?#".contains($0) }) {
            rest = rest[..<end]
        }
        // Userinfo
        var user: String? = nil
        if let at = rest.lastIndex(of: "@") {
            let info = rest[..<at]
            let name = info.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            user = name.removingPercentEncoding ?? name
            if user?.isEmpty == true { user = nil }
            rest = rest[rest.index(after: at)...]
        }

        var host: Substring
        var port: Int? = nil
        if rest.hasPrefix("[") {
            // [IPv6] or [IPv6]:port
            guard let close = rest.firstIndex(of: "]") else { return nil }
            host = rest[rest.index(after: rest.startIndex)..<close]
            let after = rest[rest.index(after: close)...]
            if after.hasPrefix(":") { port = validPort(String(after.dropFirst())) }
        } else if rest.filter({ $0 == ":" }).count == 1, let colon = rest.firstIndex(of: ":") {
            host = rest[..<colon]
            port = validPort(String(rest[rest.index(after: colon)...]))
        } else {
            host = rest // plain host, or a bare IPv6 address
        }

        guard !host.isEmpty, !host.contains(where: { $0.isWhitespace }) else { return nil }
        return HostAddress(host: String(host), port: port, user: user)
    }

    static func validPort(_ text: String) -> Int? {
        guard let port = Int(text), (1...65535).contains(port) else { return nil }
        return port
    }
}
