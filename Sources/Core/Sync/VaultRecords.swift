import Foundation
import GRDB

/// A deleted record, kept so the deletion reaches the other synced Macs. Written by the
/// v8 triggers, so every delete path (including ON DELETE CASCADE) leaves one.
public struct SyncTombstone: Codable, Equatable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "syncTombstone"

    public var tableName: String
    public var recordId: String
    public var deletedAt: Date
}

/// Every synced row of a vault. Records are copied between Macs exactly as stored: their
/// encrypted fields are bound to the record id and sealed with the shared vault key.
struct VaultRecords: Codable, Equatable {
    var groups: [HostGroup] = []
    var hosts: [SavedHost] = []
    var credentials: [Credential] = []
    var knownHosts: [KnownHost] = []
    var passwordHistory: [PasswordHistory] = []
    var tombstones: [SyncTombstone] = []

    static func read(_ db: Database) throws -> VaultRecords {
        VaultRecords(
            groups: try HostGroup.fetchAll(db),
            hosts: try SavedHost.fetchAll(db),
            credentials: try Credential.fetchAll(db),
            knownHosts: try KnownHost.fetchAll(db),
            passwordHistory: try PasswordHistory.fetchAll(db),
            tombstones: try SyncTombstone.fetchAll(db)
        ).sorted()
    }

    /// Fixed order, so two copies of the same rows compare equal.
    func sorted() -> VaultRecords {
        func byID<R: Identifiable>(_ records: [R]) -> [R] where R.ID == String {
            records.sorted { $0.id.utf8.lexicographicallyPrecedes($1.id.utf8) }
        }
        return VaultRecords(
            groups: byID(groups),
            hosts: byID(hosts),
            credentials: byID(credentials),
            knownHosts: byID(knownHosts),
            passwordHistory: byID(passwordHistory),
            tombstones: tombstones.sorted {
                $0.tableName != $1.tableName
                    ? $0.tableName.utf8.lexicographicallyPrecedes($1.tableName.utf8)
                    : $0.recordId.utf8.lexicographicallyPrecedes($1.recordId.utf8)
            }
        )
    }

    // MARK: - Merging

    /// Merges copies of a vault record by record. The latest edit of each record wins, and
    /// a deletion wins over any edit made before it. Every Mac merging the same copies gets
    /// the same result, ties included, so they converge.
    ///
    /// Then the result is made consistent: credentials and history whose host or credential
    /// is gone are dropped, hosts in a deleted group become ungrouped, and where two Macs
    /// each trusted a key for the same server, the key trusted first is kept. A Mac that had
    /// trusted a different key then reports a host key mismatch, rather than sync silently
    /// replacing a trusted key.
    static func merge(_ copies: [VaultRecords]) -> VaultRecords {
        var deletedAt: [String: SyncTombstone] = [:]
        for tombstone in copies.flatMap(\.tombstones) {
            let key = tombstoneKey(tombstone.tableName, tombstone.recordId)
            if let existing = deletedAt[key], existing.deletedAt >= tombstone.deletedAt { continue }
            deletedAt[key] = tombstone
        }

        func latest<R: Identifiable & Encodable>(
            _ table: String, _ records: [R], stamp: (R) -> Date
        ) -> [String: R] where R.ID == String {
            var winners: [String: R] = [:]
            for record in records {
                if let current = winners[record.id], !isNewer(record, stamp(record), than: current, stamp(current)) { continue }
                winners[record.id] = record
            }
            return winners.filter { id, record in
                guard let tombstone = deletedAt[tombstoneKey(table, id)] else { return true }
                return stamp(record) > tombstone.deletedAt
            }
        }

        let groups = latest("hostGroup", copies.flatMap(\.groups)) { $0.updatedAt }

        var hosts = latest("host", copies.flatMap(\.hosts)) { $0.updatedAt }
        // Connecting doesn't count as an edit, so take the latest connection from any copy.
        for host in copies.flatMap(\.hosts) {
            guard let connected = host.lastConnectedAt, var winner = hosts[host.id] else { continue }
            if winner.lastConnectedAt.map({ connected > $0 }) ?? true {
                winner.lastConnectedAt = connected
                hosts[host.id] = winner
            }
        }
        for (id, host) in hosts {
            if let groupId = host.groupId, groups[groupId] == nil {
                hosts[id]?.groupId = nil
            }
        }

        let credentials = latest("credential", copies.flatMap(\.credentials)) { $0.updatedAt }
            .filter { hosts[$0.value.hostId] != nil }
        let history = latest("passwordHistory", copies.flatMap(\.passwordHistory)) { $0.changedAt }
            .filter { credentials[$0.value.credentialId] != nil }

        var knownHosts: [String: KnownHost] = [:]
        var trustedKeyForServer: [String: KnownHost] = [:]
        for knownHost in latest("knownHost", copies.flatMap(\.knownHosts), stamp: { $0.firstSeenAt }).values {
            let server = "\(knownHost.hostname):\(knownHost.port)"
            if let kept = trustedKeyForServer[server],
               (kept.firstSeenAt, kept.id) < (knownHost.firstSeenAt, knownHost.id) { continue }
            trustedKeyForServer[server] = knownHost
        }
        for knownHost in trustedKeyForServer.values { knownHosts[knownHost.id] = knownHost }

        let alive: [String: Set<String>] = [
            "hostGroup": Set(groups.keys),
            "host": Set(hosts.keys),
            "credential": Set(credentials.keys),
            "knownHost": Set(knownHosts.keys),
            "passwordHistory": Set(history.keys),
        ]
        let tombstones = deletedAt.values.filter { alive[$0.tableName]?.contains($0.recordId) != true }

        return VaultRecords(
            groups: Array(groups.values),
            hosts: Array(hosts.values),
            credentials: Array(credentials.values),
            knownHosts: Array(knownHosts.values),
            passwordHistory: Array(history.values),
            tombstones: tombstones
        ).sorted()
    }

    /// Whether `a` should replace `b`. Equal timestamps are settled by comparing the encoded
    /// records, so every Mac picks the same one.
    static func isNewer<T: Encodable>(_ a: T, _ stampA: Date, than b: T, _ stampB: Date) -> Bool {
        if stampA != stampB { return stampA > stampB }
        return canonical(b).lexicographicallyPrecedes(canonical(a))
    }

    private static func canonical<T: Encodable>(_ value: T) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return (try? encoder.encode(value)) ?? Data()
    }

    private static func tombstoneKey(_ table: String, _ id: String) -> String { "\(table)/\(id)" }

    // MARK: - Applying

    /// Turns `local` (the rows currently in `db`) into these rows.
    func apply(over local: VaultRecords, in db: Database) throws {
        // Add and update parents before children...
        try Self.upsert(groups, over: local.groups, db)
        try Self.upsert(hosts, over: local.hosts, db)
        try Self.upsert(credentials, over: local.credentials, db)
        try Self.upsert(passwordHistory, over: local.passwordHistory, db)
        // ...a replaced trusted key can share its hostname and port, so remove first...
        try Self.delete(local.knownHosts, keeping: knownHosts, db)
        try Self.upsert(knownHosts, over: local.knownHosts, db)
        // ...then remove children before parents.
        try Self.delete(local.passwordHistory, keeping: passwordHistory, db)
        try Self.delete(local.credentials, keeping: credentials, db)
        try Self.delete(local.hosts, keeping: hosts, db)
        try Self.delete(local.groups, keeping: groups, db)

        // The deletions above left tombstones dated now; keep the merged dates instead.
        try SyncTombstone.deleteAll(db)
        for tombstone in tombstones {
            try tombstone.insert(db)
        }
    }

    private static func upsert<R: PersistableRecord & Identifiable & Equatable>(
        _ records: [R], over local: [R], _ db: Database
    ) throws where R.ID == String {
        let existing = Dictionary(local.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for record in records where existing[record.id] != record {
            try record.save(db)
        }
    }

    private static func delete<R: PersistableRecord & Identifiable>(
        _ local: [R], keeping records: [R], _ db: Database
    ) throws where R.ID == String {
        let keep = Set(records.map(\.id))
        for record in local where !keep.contains(record.id) {
            _ = try record.delete(db)
        }
    }
}
