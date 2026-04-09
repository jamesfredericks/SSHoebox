import SwiftUI
import SSHoeboxCore

/// Compact menu-bar popover shown via MenuBarExtra.
/// Shows vault status and quick-connect shortcuts.
struct MenuBarView: View {
    @ObservedObject var viewModel: VaultViewModel
    @EnvironmentObject var sessionRegistry: TerminalSessionRegistry

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack(spacing: 10) {
                Image(systemName: viewModel.isUnlocked ? "lock.open.fill" : "lock.fill")
                    .font(.system(size: 14))
                    .foregroundStyle(viewModel.isUnlocked ? .green : .orange)

                VStack(alignment: .leading, spacing: 1) {
                    Text("SSHoebox")
                        .font(.system(size: 13, weight: .semibold))
                    Text(viewModel.isUnlocked ? "Vault unlocked" : "Vault locked")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if viewModel.isUnlocked {
                    let active = sessionRegistry.totalActiveConnections
                    if active > 0 {
                        Text("\(active) active")
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.green.opacity(0.15))
                            .foregroundStyle(.green)
                            .clipShape(Capsule())
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)

            Divider()

            if viewModel.isUnlocked {
                // Quick actions
                MenuBarButton(icon: "macwindow", label: "Open SSHoebox") {
                    NSApp.activate(ignoringOtherApps: true)
                    NSApp.windows.first?.makeKeyAndOrderFront(nil)
                }

                Divider().padding(.horizontal, 8)

                MenuBarButton(icon: "lock.fill", label: "Lock Vault") {
                    viewModel.lock()
                }
            } else {
                MenuBarButton(icon: "macwindow", label: "Unlock Vault…") {
                    NSApp.activate(ignoringOtherApps: true)
                    NSApp.windows.first?.makeKeyAndOrderFront(nil)
                }
            }

            Divider().padding(.horizontal, 8)

            MenuBarButton(icon: "xmark.circle", label: "Quit") {
                NSApp.terminate(nil)
            }
        }
        .frame(width: 220)
    }
}

private struct MenuBarButton: View {
    let icon: String
    let label: String
    let action: () -> Void
    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 12))
                    .frame(width: 16, alignment: .center)
                Text(label)
                    .font(.system(size: 13))
                Spacer()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .background(isHovering ? Color.accentColor.opacity(0.15) : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
    }
}
