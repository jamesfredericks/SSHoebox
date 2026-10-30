import Foundation

/// Parses an OpenSSH client config file (~/.ssh/config) into structured host entries.
///
/// Follows `ssh_config(5)` closely enough for import:
/// - Keywords are case-insensitive; `Key Value`, `Key=Value` and `Key = Value` are all accepted.
/// - Arguments may be quoted (`"..."` or `'...'`); `#` outside quotes starts a comment.
/// - Each concrete pattern on a `Host` line (`Host a b`) becomes its own entry. Patterns
///   containing `*`, `?` or a leading `!` are never imported, but still apply their
///   options to the hosts they match.
/// - Each entry is resolved like `ssh -G <alias>`: every block whose patterns match the
///   alias contributes, and the FIRST value obtained for an option wins.
/// - `Match` blocks are not evaluated (their criteria depend on runtime state), so their
///   options are ignored. `Match all` is treated as matching every host.
/// - `Include` is followed when parsing from a file (globs, `~`, paths relative to the
///   top-level file's directory, max depth 16). `parse(string:)` has no file context, so
///   there it is ignored unless an `includeBaseDirectory` is supplied.
public struct SSHConfigParser {

    public struct ConfigHost {
        public let alias: String          // The "Host" pattern (used as display name)
        public let hostname: String       // Resolved HostName (or alias if not specified)
        public let port: Int              // Default 22
        public let user: String           // User directive (may be empty)
        public let identityFile: String?  // First IdentityFile path (may be empty)
    }

    /// OpenSSH's limit on nested `Include`s.
    private static let maxIncludeDepth = 16

    /// A single non-empty, non-comment config line, split into keyword and arguments.
    struct Directive: Equatable {
        let keyword: String   // lowercased
        let args: [String]
    }

    /// Parse an SSH config file at the given path. `Include` paths are resolved relative
    /// to the file's directory (`~/.ssh` for the user config, matching OpenSSH).
    public static func parse(contentsOf url: URL) throws -> [ConfigHost] {
        let content = try String(contentsOf: url, encoding: .utf8)
        return parse(string: content, includeBaseDirectory: url.deletingLastPathComponent())
    }

    /// Parse SSH config from a string. `Include` directives are ignored unless
    /// `includeBaseDirectory` is given.
    public static func parse(string: String, includeBaseDirectory: URL? = nil) -> [ConfigHost] {
        let directives = expandIncludes(tokenize(string), baseDirectory: includeBaseDirectory, depth: 0)

        // Concrete aliases in order of first appearance, de-duplicated case-insensitively
        var aliases: [String] = []
        var seen: Set<String> = []
        for directive in directives where directive.keyword == "host" {
            for pattern in directive.args where isConcrete(pattern) {
                if seen.insert(pattern.lowercased()).inserted {
                    aliases.append(pattern)
                }
            }
        }

        return aliases.compactMap { resolve(alias: $0, directives: directives) }
    }

    // MARK: - Resolution

    /// Evaluates the config for one alias, keeping the first value obtained for each option.
    private static func resolve(alias: String, directives: [Directive]) -> ConfigHost? {
        var hostname: String? = nil
        var port: Int? = nil
        var user: String? = nil
        var identityFile: String? = nil

        // Lines before the first Host/Match apply to every host
        var active = true
        for directive in directives {
            switch directive.keyword {
            case "host":
                active = hostPatternsMatch(directive.args, alias: alias)
                continue
            case "match":
                active = directive.args.count == 1 && directive.args[0].lowercased() == "all"
                continue
            default:
                break
            }
            guard active, let value = directive.args.first else { continue }

            switch directive.keyword {
            case "hostname" where hostname == nil:
                hostname = expandHostnameTokens(value, alias: alias)
            case "port" where port == nil:
                // Ignore invalid values rather than letting them shadow a later valid one
                if let p = Int(value), (1...65535).contains(p) { port = p }
            case "user" where user == nil:
                user = value
            case "identityfile" where identityFile == nil:
                identityFile = (value as NSString).expandingTildeInPath
            default:
                break
            }
        }

        let resolvedHostname = (hostname?.isEmpty == false) ? hostname! : alias
        return ConfigHost(
            alias: alias,
            hostname: resolvedHostname,
            port: port ?? 22,
            user: user ?? "",
            identityFile: identityFile
        )
    }

    /// A pattern that names a single host (no wildcards or negation).
    private static func isConcrete(_ pattern: String) -> Bool {
        !pattern.isEmpty && !pattern.contains("*") && !pattern.contains("?") && !pattern.hasPrefix("!")
    }

    /// `Host` semantics: matches if any positive pattern matches and no negated pattern does.
    static func hostPatternsMatch(_ patterns: [String], alias: String) -> Bool {
        let host = alias.lowercased()
        var matched = false
        for pattern in patterns {
            if pattern.hasPrefix("!") {
                if globMatch(String(pattern.dropFirst()).lowercased(), host) { return false }
            } else if globMatch(pattern.lowercased(), host) {
                matched = true
            }
        }
        return matched
    }

    /// `*` matches any run of characters, `?` exactly one.
    static func globMatch(_ pattern: String, _ text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0
        var starP = -1, starT = 0
        while ti < t.count {
            if pi < p.count && (p[pi] == "?" || p[pi] == t[ti]) {
                pi += 1; ti += 1
            } else if pi < p.count && p[pi] == "*" {
                starP = pi; starT = ti; pi += 1
            } else if starP >= 0 {
                pi = starP + 1; starT += 1; ti = starT
            } else {
                return false
            }
        }
        while pi < p.count && p[pi] == "*" { pi += 1 }
        return pi == p.count
    }

    /// HostName accepts `%h` (the alias) and `%%`.
    private static func expandHostnameTokens(_ value: String, alias: String) -> String {
        guard value.contains("%") else { return value }
        var result = ""
        var iterator = value.makeIterator()
        while let c = iterator.next() {
            guard c == "%" else { result.append(c); continue }
            switch iterator.next() {
            case "h": result += alias
            case "%": result.append("%")
            case let other?: result.append("%"); result.append(other)
            case nil: result.append("%")
            }
        }
        return result
    }

    // MARK: - Include

    private static func expandIncludes(_ directives: [Directive], baseDirectory: URL?, depth: Int) -> [Directive] {
        var result: [Directive] = []
        for directive in directives {
            guard directive.keyword == "include" else {
                result.append(directive)
                continue
            }
            guard let base = baseDirectory, depth < maxIncludeDepth else { continue }
            for pattern in directive.args {
                for path in globPaths(pattern, baseDirectory: base) {
                    guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
                    result += expandIncludes(tokenize(content), baseDirectory: base, depth: depth + 1)
                }
            }
        }
        return result
    }

    /// Expands `~` and shell globs; relative paths are resolved against `baseDirectory`.
    private static func globPaths(_ pattern: String, baseDirectory: URL) -> [String] {
        var path = (pattern as NSString).expandingTildeInPath
        if !path.hasPrefix("/") {
            path = baseDirectory.appendingPathComponent(path).path
        }
        var g = glob_t()
        defer { globfree(&g) }
        guard glob(path, 0, nil, &g) == 0 else { return [] }
        return (0..<Int(g.gl_pathc)).compactMap { i in
            g.gl_pathv[i].flatMap { String(cString: $0) }
        }
    }

    // MARK: - Tokenizer

    static func tokenize(_ string: String) -> [Directive] {
        string.components(separatedBy: .newlines).compactMap(parseLine)
    }

    /// Splits a line the way OpenSSH does: the keyword ends at whitespace or `=`, an
    /// optional `=` may follow, then the rest is split into (optionally quoted) arguments.
    static func parseLine(_ line: String) -> Directive? {
        let chars = Array(line)
        var i = 0
        func skipWhitespace() { while i < chars.count && (chars[i] == " " || chars[i] == "\t") { i += 1 } }

        skipWhitespace()
        var keyword = ""
        while i < chars.count && chars[i] != " " && chars[i] != "\t" && chars[i] != "=" {
            keyword.append(chars[i]); i += 1
        }
        if keyword.isEmpty || keyword.hasPrefix("#") { return nil }
        skipWhitespace()
        if i < chars.count && chars[i] == "=" { i += 1 }

        guard let args = splitArguments(chars[i...]), !args.isEmpty else { return nil }
        return Directive(keyword: keyword.lowercased(), args: args)
    }

    /// Whitespace-separated arguments with `"`/`'` quoting and `\` escapes for quotes,
    /// backslash and (outside quotes) space. Returns nil for an unterminated quote.
    private static func splitArguments(_ chars: ArraySlice<Character>) -> [String]? {
        var args: [String] = []
        var current = ""
        var inArg = false
        var quote: Character? = nil
        var i = chars.startIndex
        while i < chars.endIndex {
            let c = chars[i]
            if quote == nil && (c == " " || c == "\t") {
                if inArg { args.append(current); current = ""; inArg = false }
            } else if quote == nil && c == "#" && !inArg {
                break // comment
            } else if c == "\\", i + 1 < chars.endIndex,
                      ["\"", "'", "\\"].contains(chars[i + 1]) || (quote == nil && chars[i + 1] == " ") {
                current.append(chars[i + 1]); inArg = true; i += 1
            } else if quote == nil && (c == "\"" || c == "'") {
                quote = c; inArg = true
            } else if c == quote {
                quote = nil
            } else {
                current.append(c); inArg = true
            }
            i += 1
        }
        if quote != nil { return nil }
        if inArg { args.append(current) }
        return args
    }
}
