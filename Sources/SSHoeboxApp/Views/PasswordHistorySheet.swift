import SwiftUI
import SSHoeboxCore
import CryptoKit

struct PasswordHistorySheet: View {
    let credential: Credential
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey

    @State private var history: [PasswordHistory] = []
    @State private var copiedId: String? = nil
    @Environment(\.dismiss) private var dismiss

    private var repo: PasswordHistoryRepository { PasswordHistoryRepository(dbManager: dbManager) }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Password History")
                    .font(DesignSystem.Typography.heading())
                    .foregroundStyle(DesignSystem.Colors.textPrimary)
                Spacer()
                Button("Done") { dismiss() }
                    .buttonStyle(.plain)
                    .foregroundStyle(DesignSystem.Colors.accent)
            }
            .padding(DesignSystem.Spacing.large)

            Divider()

            if history.isEmpty {
                EmptyStateView(
                    title: "No History",
                    description: "Previous secrets are saved here when you update a credential.",
                    systemImage: "clock.arrow.circlepath"
                )
            } else {
                List {
                    ForEach(history) { entry in
                        HistoryRow(
                            entry: entry,
                            isCopied: copiedId == entry.id,
                            onCopy: { copyEntry(entry) },
                            onDelete: { deleteEntry(entry) }
                        )
                    }
                }
                .listStyle(.plain)
            }
        }
        .frame(width: 420, height: 380)
        .background(DesignSystem.Colors.background)
        .onAppear { loadHistory() }
    }

    private func loadHistory() {
        history = (try? repo.getAll(for: credential.id)) ?? []
    }

    private func copyEntry(_ entry: PasswordHistory) {
        guard let secret = try? repo.decrypt(entry, vaultKey: vaultKey) else { return }
        ClipboardManager.shared.copy(secret)
        copiedId = entry.id
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if copiedId == entry.id { copiedId = nil }
        }
    }

    private func deleteEntry(_ entry: PasswordHistory) {
        try? repo.delete(entry)
        history.removeAll { $0.id == entry.id }
    }
}

// MARK: - HistoryRow

private struct HistoryRow: View {
    let entry: PasswordHistory
    let isCopied: Bool
    let onCopy: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Changed \(entry.changedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(DesignSystem.Typography.body())
                    .foregroundStyle(DesignSystem.Colors.textPrimary)
                Text("Tap copy to retrieve this secret")
                    .font(DesignSystem.Typography.label())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }

            Spacer()

            Button(action: onCopy) {
                Image(systemName: isCopied ? "checkmark" : "doc.on.doc")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(isCopied ? Color.green : DesignSystem.Colors.accent)
                    .frame(width: 30, height: 30)
                    .background(
                        (isCopied ? Color.green : DesignSystem.Colors.accent).opacity(0.1)
                    )
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)

            Button(action: onDelete) {
                Image(systemName: "trash")
                    .font(.system(size: 13))
                    .foregroundStyle(.red.opacity(0.7))
                    .frame(width: 30, height: 30)
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 4)
    }
}
