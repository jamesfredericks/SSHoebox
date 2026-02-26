import SwiftUI
import SSHoeboxCore

struct ManageGroupsSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: HostsViewModel

    @State private var newGroupName = ""
    @State private var editingGroup: HostGroup? = nil
    @State private var editingName = ""
    @State private var showDeleteAlert = false
    @State private var groupToDelete: HostGroup? = nil

    var body: some View {
        NavigationStack {
            List {
                // New group input
                Section {
                    HStack {
                        TextField("New group name…", text: $newGroupName)
                            .onSubmit { createGroup() }
                        Button {
                            createGroup()
                        } label: {
                            Image(systemName: "plus.circle.fill")
                                .foregroundStyle(DesignSystem.Colors.accent)
                                .font(.title3)
                        }
                        .buttonStyle(.plain)
                        .disabled(newGroupName.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: {
                    Text("New Group")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }

                // Existing groups
                if !viewModel.groups.isEmpty {
                    Section {
                        ForEach(viewModel.groups) { group in
                            HStack {
                                if editingGroup?.id == group.id {
                                    TextField("Group name", text: $editingName)
                                        .onSubmit { commitRename() }
                                    Spacer()
                                    Button("Done") { commitRename() }
                                        .foregroundStyle(DesignSystem.Colors.accent)
                                } else {
                                    HStack(spacing: 10) {
                                        Image(systemName: "folder.fill")
                                            .foregroundStyle(DesignSystem.Colors.accent.opacity(0.8))
                                        Text(group.name)
                                            .foregroundStyle(DesignSystem.Colors.textPrimary)

                                        Spacer()

                                        let count = viewModel.hosts.filter { $0.groupId == group.id }.count
                                        Text("\(count)")
                                            .font(.caption)
                                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 2)
                                            .background(DesignSystem.Colors.surface)
                                            .clipShape(Capsule())
                                    }
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        editingGroup = group
                                        editingName = group.name
                                    }
                                }
                            }
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) {
                                    groupToDelete = group
                                    showDeleteAlert = true
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                        .onMove { from, to in
                            var reordered = viewModel.groups
                            reordered.move(fromOffsets: from, toOffset: to)
                            viewModel.reorderGroups(reordered)
                        }
                    } header: {
                        Text("Groups")
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                    } footer: {
                        Text("Tap a group to rename it. Deleting a group moves its hosts to Ungrouped.")
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                    }
                }
            }
            .listStyle(.inset)
            .scrollContentBackground(.hidden)
            .background(DesignSystem.Colors.background)
            .navigationTitle("Manage Groups")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Delete Group", isPresented: $showDeleteAlert, presenting: groupToDelete) { group in
                Button("Delete", role: .destructive) {
                    viewModel.deleteGroup(group)
                }
                Button("Cancel", role: .cancel) { }
            } message: { group in
                Text("'\(group.name)' will be deleted. Its hosts will become ungrouped.")
            }
        }
        .frame(minWidth: 380, minHeight: 420)
        .background(DesignSystem.Colors.background)
    }

    private func createGroup() {
        let name = newGroupName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        viewModel.addGroup(name: name)
        newGroupName = ""
    }

    private func commitRename() {
        guard let group = editingGroup else { return }
        let name = editingName.trimmingCharacters(in: .whitespaces)
        if !name.isEmpty {
            viewModel.updateGroup(group, name: name)
        }
        editingGroup = nil
    }
}
