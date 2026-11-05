import SwiftUI
import CryptoKit
import SSHoeboxCore

/// ⌘K: type part of a host's name, address, user or tag and press Return to connect.
/// ⌘Return opens its files instead, ⇧Return opens another terminal tab, ⌥Return just shows it.
struct QuickConnectView: View {
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    @EnvironmentObject private var navigator: AppNavigator
    @Environment(\.dismiss) private var dismiss

    @State private var query = ""
    @State private var hosts: [SavedHost] = []
    @State private var selection = 0
    @FocusState private var searchFocused: Bool

    private struct Row: Identifiable {
        let host: SavedHost
        let name: String
        let address: String
        let tags: [String]
        let isFavorite: Bool
        var id: String { host.id }
    }

    private var rows: [Row] {
        let matching = hosts.filter { HostSearch.matches($0, query: query, vaultKey: vaultKey) }
        let rows = matching.map { host -> Row in
            let options = host.decryptedOptions(using: vaultKey)
            let user = host.decryptedUser(using: vaultKey)
            let address = (user.isEmpty ? "" : "\(user)@") + host.decryptedHostname(using: vaultKey)
                + (host.port == 22 ? "" : ":\(host.port)")
            return Row(host: host, name: host.decryptedName(using: vaultKey), address: address,
                       tags: options.tags, isFavorite: options.isFavorite)
        }
        // Best name match first; then favorites; then most recently used; then by name.
        return rows.sorted { a, b in
            let sa = HostSearch.score(a.host, query: query, vaultKey: vaultKey)
            let sb = HostSearch.score(b.host, query: query, vaultKey: vaultKey)
            if sa != sb { return sa > sb }
            if a.isFavorite != b.isFavorite { return a.isFavorite }
            let ra = a.host.lastConnectedAt ?? .distantPast, rb = b.host.lastConnectedAt ?? .distantPast
            if ra != rb { return ra > rb }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
    }

    var body: some View {
        let rows = self.rows
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "bolt.horizontal.circle")
                    .font(.system(size: 18))
                    .foregroundStyle(DesignSystem.Colors.accent)
                TextField("Connect to…", text: $query, prompt: Text("Host name, address, user or #tag"))
                    .textFieldStyle(.plain)
                    .font(.system(size: 18))
                    .focused($searchFocused)
                    .onSubmit { open(rows, action: .terminal) }
                    .onKeyPress(.downArrow) {
                        selection = min(selection + 1, max(rows.count - 1, 0))
                        return .handled
                    }
                    .onKeyPress(.upArrow) {
                        selection = max(selection - 1, 0)
                        return .handled
                    }
                    .onKeyPress(.return, phases: .down) { press in
                        if press.modifiers.contains(.command) { open(rows, action: .files); return .handled }
                        if press.modifiers.contains(.shift) { open(rows, action: .newTerminal); return .handled }
                        if press.modifiers.contains(.option) { open(rows, action: .show); return .handled }
                        return .ignored
                    }
                    .onKeyPress(.escape) {
                        dismiss()
                        return .handled
                    }
            }
            .padding(14)

            Divider()

            if rows.isEmpty {
                Text(hosts.isEmpty ? "No hosts yet. Add one in the Hosts list." : "No hosts match \"\(query)\".")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .frame(maxWidth: .infinity, minHeight: 80)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 2) {
                            ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                                rowView(row, selected: index == selection)
                                    .id(row.id)
                                    .onTapGesture(count: 2) {
                                        selection = index
                                        open(rows, action: .terminal)
                                    }
                                    .onTapGesture { selection = index }
                            }
                        }
                        .padding(6)
                    }
                    .frame(maxHeight: 340)
                    .onChange(of: selection) { _, index in
                        guard rows.indices.contains(index) else { return }
                        proxy.scrollTo(rows[index].id)
                    }
                }
            }

            Divider()

            HStack(spacing: 14) {
                hint("↩", "Terminal")
                hint("⇧↩", "New tab")
                hint("⌘↩", "Files")
                hint("⌥↩", "Show")
                Spacer()
                hint("esc", "Close")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
        }
        .frame(width: 560)
        .background(DesignSystem.Colors.background)
        .onAppear {
            hosts = (try? HostRepository(dbManager: dbManager).getAll()) ?? []
            searchFocused = true
        }
        .onChange(of: query) { selection = 0 }
    }

    private func rowView(_ row: Row, selected: Bool) -> some View {
        HStack(spacing: 10) {
            Image(systemName: row.isFavorite ? "star.fill" : "server.rack")
                .foregroundStyle(row.isFavorite ? Color.yellow : DesignSystem.Colors.textSecondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(row.name)
                    .foregroundStyle(DesignSystem.Colors.textPrimary)
                Text(row.address)
                    .font(DesignSystem.Typography.mono())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            Spacer()
            ForEach(row.tags.prefix(3), id: \.self) { tag in
                TagChip(tag: tag)
            }
            if let last = row.host.lastConnectedAt {
                Text(last.formatted(.relative(presentation: .named)))
                    .font(.caption2)
                    .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.7))
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 6).fill(selected ? DesignSystem.Colors.accent.opacity(0.18) : .clear))
        .contentShape(Rectangle())
    }

    private func hint(_ key: String, _ label: String) -> some View {
        HStack(spacing: 4) {
            Text(key)
                .font(.caption.monospaced())
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(RoundedRectangle(cornerRadius: 4).fill(DesignSystem.Colors.surface))
            Text(label)
                .font(.caption)
        }
        .foregroundStyle(DesignSystem.Colors.textSecondary)
    }

    private func open(_ rows: [Row], action: AppNavigator.HostAction) {
        guard rows.indices.contains(selection) else { return }
        let hostId = rows[selection].host.id
        dismiss()
        navigator.open(hostId: hostId, action: action)
    }
}

/// A small rounded label for a host tag.
struct TagChip: View {
    let tag: String

    var body: some View {
        Text(tag)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(DesignSystem.Colors.accent.opacity(0.12)))
            .foregroundStyle(DesignSystem.Colors.accent)
    }
}
