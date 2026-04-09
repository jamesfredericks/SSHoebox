import SwiftUI
import SSHoeboxCore

/// A persistent in-app badge shown at the bottom of the window while a secret is on the clipboard.
/// Displays a countdown and a "Clear Now" button.
struct ClipboardStatusBadge: View {
    @ObservedObject var clipboard = ClipboardManager.shared

    var body: some View {
        if clipboard.isActive {
            HStack(spacing: 8) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 11))

                Text("Secret on clipboard")
                    .font(DesignSystem.Typography.label())

                Text("·")
                    .foregroundStyle(.orange.opacity(0.6))

                Text("clears in \(clipboard.secondsRemaining)s")
                    .font(DesignSystem.Typography.label())
                    .monospacedDigit()

                Divider()
                    .frame(height: 14)
                    .background(.orange.opacity(0.4))

                Button("Clear Now") {
                    clipboard.clearNow()
                }
                .buttonStyle(.plain)
                .font(DesignSystem.Typography.label())
                .foregroundStyle(.orange)
            }
            .foregroundStyle(.orange)
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.orange.opacity(0.12))
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.orange.opacity(0.35), lineWidth: 1)
                    )
            )
            .padding(DesignSystem.Spacing.medium)
            .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }
}
