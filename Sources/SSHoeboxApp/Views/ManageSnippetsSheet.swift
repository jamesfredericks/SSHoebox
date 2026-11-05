import SwiftUI
import CryptoKit
import SSHoeboxCore

/// Add, edit and delete snippets: this host's own and the ones offered for every host.
struct ManageSnippetsSheet: View {
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    let hostId: String?
    let hostName: String?
    @Environment(\.dismiss) private var dismiss

    private struct Item: Identifiable, Equatable {
        let id: String
        var name: String
        var command: String
        var isGlobal: Bool
    }

    @State private var items: [Item] = []
    @State private var editing: Item?
    @State private var errorMessage: String?

    private var repository: SnippetRepository { SnippetRepository(dbManager: dbManager) }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Snippets").font(DesignSystem.Typography.heading())
                Spacer()
                Button {
                    editing = Item(id: UUID().uuidString, name: "", command: "", isGlobal: hostId == nil)
                } label: {
                    Label("New Snippet", systemImage: "plus")
                }
            }
            .padding(DesignSystem.Spacing.large)

            Divider()

            if items.isEmpty {
                EmptyStateView(title: "No Snippets",
                               description: "Save commands you run often, then send them from the terminal's snippets menu.",
                               systemImage: "text.badge.plus")
                    .frame(maxHeight: .infinity)
            } else {
                List {
                    ForEach(items) { item in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(item.name).foregroundStyle(DesignSystem.Colors.textPrimary)
                                    Text(item.isGlobal ? "All hosts" : (hostName ?? "This host"))
                                        .font(.caption2)
                                        .padding(.horizontal, 5)
                                        .background(Capsule().fill(DesignSystem.Colors.surface))
                                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                                }
                                Text(item.command)
                                    .font(DesignSystem.Typography.mono())
                                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                                    .lineLimit(2)
                            }
                            Spacer()
                            Button("Edit") { editing = item }
                            Button(role: .destructive) { delete(item) } label: { Image(systemName: "trash") }
                                .buttonStyle(.borderless)
                        }
                        .padding(.vertical, 2)
                    }
                }
            }

            if let errorMessage {
                Text(errorMessage).font(.caption).foregroundStyle(.red).padding(.horizontal)
            }

            Divider()
            HStack {
                Text("Click a snippet to run it in the current session; ⌥-click types it without pressing Return.")
                    .font(.caption)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(DesignSystem.Spacing.large)
        }
        .frame(width: 560, height: 460)
        .background(DesignSystem.Colors.background)
        .onAppear(perform: load)
        .sheet(item: $editing) { item in
            SnippetEditor(item: item, canBeHostSpecific: hostId != nil, hostName: hostName) { saved in
                save(saved)
            }
        }
    }

    private func load() {
        do {
            let snippets = try hostId.map { try repository.snippets(forHost: $0) } ?? repository.snippets(forHost: nil)
            items = snippets.map {
                Item(id: $0.id, name: $0.decryptedName(using: vaultKey), command: $0.decryptedCommand(using: vaultKey),
                     isGlobal: $0.hostId == nil)
            }
            errorMessage = nil
        } catch {
            errorMessage = "Couldn't load snippets: \(error.localizedDescription)"
        }
    }

    private func save(_ item: Item) {
        do {
            try repository.save(id: item.id, hostId: item.isGlobal ? nil : hostId, name: item.name,
                                command: item.command, vaultKey: vaultKey)
            load()
        } catch {
            errorMessage = "Couldn't save the snippet: \(error.localizedDescription)"
        }
    }

    private func delete(_ item: Item) {
        do {
            if let snippet = try repository.getAll().first(where: { $0.id == item.id }) {
                try repository.delete(snippet)
            }
            load()
        } catch {
            errorMessage = "Couldn't delete the snippet: \(error.localizedDescription)"
        }
    }

    private struct SnippetEditor: View {
        @State var item: Item
        let canBeHostSpecific: Bool
        let hostName: String?
        let onSave: (Item) -> Void
        @Environment(\.dismiss) private var dismiss

        var body: some View {
            NavigationStack {
                Form {
                    TextField("Name", text: $item.name, prompt: Text("e.g. Tail syslog"))
                    VStack(alignment: .leading) {
                        Text("Command").font(.caption).foregroundStyle(DesignSystem.Colors.textSecondary)
                        TextEditor(text: $item.command)
                            .font(DesignSystem.Typography.mono())
                            .frame(minHeight: 90)
                            .autocorrectionDisabled()
                    }
                    if canBeHostSpecific {
                        Picker("Offered for", selection: $item.isGlobal) {
                            Text("All hosts").tag(true)
                            Text(hostName.map { "Only \($0)" } ?? "Only this host").tag(false)
                        }
                    }
                }
                .formStyle(.grouped)
                .navigationTitle(item.name.isEmpty ? "New Snippet" : "Edit Snippet")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            onSave(item)
                            dismiss()
                        }
                        .disabled(item.name.trimmingCharacters(in: .whitespaces).isEmpty
                                  || item.command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
            }
            .frame(width: 460, height: 340)
        }
    }
}
