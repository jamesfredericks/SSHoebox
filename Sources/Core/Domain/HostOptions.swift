import Foundation

/// Per-host connection settings beyond address and credentials. Stored encrypted in
/// `SavedHost.encryptedOptions`, so a new setting needs no schema change: add it here with a
/// default and decode it with `decodeIfPresent`, so options saved by older versions still read.
public struct HostOptions: Codable, Equatable, Sendable {
    /// Another saved host to connect through first (`ssh -J`). That host may have a jump host
    /// of its own, which makes a chain.
    public var jumpHostId: String?
    /// Seconds between keep-alives (`ServerAliveInterval`). Nil uses the Preferences default;
    /// 0 turns them off for this host.
    public var keepAliveInterval: Int?
    /// Local port forwards (`ssh -L`) opened with the host's terminal sessions.
    public var portForwards: [PortForward]
    /// Typed into the shell once a terminal session starts, e.g. `sudo -i` or `cd /var/log`.
    public var startupCommand: String?
    /// Free-form labels for finding hosts (search matches them).
    public var tags: [String]
    /// Pinned to the Favorites section at the top of the host list.
    public var isFavorite: Bool

    public init(jumpHostId: String? = nil,
                keepAliveInterval: Int? = nil,
                portForwards: [PortForward] = [],
                startupCommand: String? = nil,
                tags: [String] = [],
                isFavorite: Bool = false) {
        self.jumpHostId = jumpHostId
        self.keepAliveInterval = keepAliveInterval
        self.portForwards = portForwards
        self.startupCommand = startupCommand
        self.tags = tags
        self.isFavorite = isFavorite
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        jumpHostId = try c.decodeIfPresent(String.self, forKey: .jumpHostId)
        keepAliveInterval = try c.decodeIfPresent(Int.self, forKey: .keepAliveInterval)
        portForwards = try c.decodeIfPresent([PortForward].self, forKey: .portForwards) ?? []
        startupCommand = try c.decodeIfPresent(String.self, forKey: .startupCommand)
        tags = try c.decodeIfPresent([String].self, forKey: .tags) ?? []
        isFavorite = try c.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
    }

    /// The startup command, or nil if it's blank.
    public var effectiveStartupCommand: String? {
        guard let command = startupCommand?.trimmingCharacters(in: .whitespacesAndNewlines), !command.isEmpty else {
            return nil
        }
        return command
    }

    /// Tags parsed from a comma-separated field, trimmed, without blanks or duplicates.
    public static func tags(fromList text: String) -> [String] {
        var seen = Set<String>()
        return text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0.lowercased()).inserted }
    }
}

/// A local port forward: connections to `bindAddress:localPort` on this Mac are carried over
/// SSH to `remoteHost:remotePort` as seen from the server, like `ssh -L`.
public struct PortForward: Codable, Equatable, Hashable, Identifiable, Sendable {
    public var id: String
    public var localPort: Int
    public var remoteHost: String
    public var remotePort: Int
    /// Opened automatically when a terminal session to the host connects. Otherwise it's
    /// started from the session's Tunnels menu.
    public var autoStart: Bool
    /// Where to listen. Loopback by default, so only this Mac can use the tunnel.
    public var bindAddress: String

    public init(id: String = UUID().uuidString,
                localPort: Int,
                remoteHost: String,
                remotePort: Int,
                autoStart: Bool = true,
                bindAddress: String = "127.0.0.1") {
        self.id = id
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.autoStart = autoStart
        self.bindAddress = bindAddress
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        localPort = try c.decode(Int.self, forKey: .localPort)
        remoteHost = try c.decode(String.self, forKey: .remoteHost)
        remotePort = try c.decode(Int.self, forKey: .remotePort)
        autoStart = try c.decodeIfPresent(Bool.self, forKey: .autoStart) ?? true
        bindAddress = try c.decodeIfPresent(String.self, forKey: .bindAddress) ?? "127.0.0.1"
    }

    /// `8080 → db.internal:5432`, as `ssh -L` would spell it.
    public var summary: String {
        let local = bindAddress == "127.0.0.1" ? "\(localPort)" : "\(bindAddress):\(localPort)"
        return "\(local) → \(remoteHost):\(remotePort)"
    }

    /// Whether the ports are in range and there's a destination.
    public var isValid: Bool {
        (1...65535).contains(localPort) && (1...65535).contains(remotePort)
            && !remoteHost.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// Parses an `ssh -L` / `LocalForward` spec: `[bind:]port host:hostport` (config form,
    /// space-separated) or `[bind:]port:host:hostport` (command-line form). IPv6 hosts may be
    /// bracketed. Returns nil for anything else, such as Unix socket forwards.
    public static func parse(_ spec: String) -> PortForward? {
        let trimmed = spec.trimmingCharacters(in: .whitespaces)
        var fields: [String] = []
        // Split on ':' and whitespace, keeping [bracketed] IPv6 addresses whole.
        var current = ""
        var inBrackets = false
        for ch in trimmed {
            switch ch {
            case "[": inBrackets = true
            case "]": inBrackets = false
            case ":" where !inBrackets, " " where !inBrackets, "\t" where !inBrackets:
                if !current.isEmpty || ch == ":" { fields.append(current) }
                current = ""
            default: current.append(ch)
            }
        }
        fields.append(current)
        fields = fields.filter { !$0.isEmpty }

        let bind: String
        let rest: ArraySlice<String>
        switch fields.count {
        case 3: (bind, rest) = ("127.0.0.1", fields[...])
        case 4:
            let address = fields[0]
            bind = (address == "localhost" || address == "*") ? (address == "*" ? "0.0.0.0" : "127.0.0.1") : address
            rest = fields[1...]
        default: return nil
        }
        let parts = Array(rest)
        guard let local = Int(parts[0]), let remote = Int(parts[2]) else { return nil }
        let forward = PortForward(localPort: local, remoteHost: parts[1], remotePort: remote, bindAddress: bind)
        return forward.isValid ? forward : nil
    }
}
