import SwiftUI
import SSHoeboxCore

/// Every open terminal session, from all hosts, side by side. Sessions in the broadcast
/// group (orange) all receive what's typed in any of them, for running one command on a set
/// of servers.
struct SessionsWorkspaceView: View {
    @EnvironmentObject private var registry: TerminalSessionRegistry
    @EnvironmentObject private var navigator: AppNavigator
    @State private var selectedId: UUID?
    @State private var broadcastCommand = ""

    var body: some View {
        let sessions = registry.allSessions
        VStack(spacing: 0) {
            if sessions.isEmpty {
                EmptyStateView(title: "No Open Sessions",
                               description: "Terminal sessions you open on any host appear here side by side. Press ⌘K to connect.",
                               systemImage: "rectangle.split.3x3")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                toolbar(sessions)
                Divider()
                SessionGrid(sessions: sessions, selectedId: selectedId ?? sessions.first?.id, showHostName: true) { session in
                    selectedId = session.id
                }
                .overlay(alignment: .top) {
                    if !registry.broadcastIDs.isEmpty {
                        BroadcastBanner(count: registry.broadcastIDs.count)
                    }
                }
            }
        }
        .background(DesignSystem.Colors.background)
        .navigationTitle("Sessions")
    }

    private func toolbar(_ sessions: [TerminalSession]) -> some View {
        let allOn = sessions.allSatisfy(registry.isBroadcasting)
        return HStack(spacing: 10) {
            Text("\(sessions.count) session\(sessions.count == 1 ? "" : "s")")
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            Toggle(isOn: Binding(get: { allOn }, set: { registry.setBroadcast($0, for: sessions) })) {
                Label("Broadcast to all", systemImage: "dot.radiowaves.left.and.right")
            }
            .toggleStyle(.button)
            .tint(.orange)
            .help("Put every session in the broadcast group, or take them all out")

            Divider().frame(height: 18)

            // One line to all broadcast sessions, without typing it in a terminal first.
            TextField("Send a command to the broadcast group…", text: $broadcastCommand)
                .textFieldStyle(.roundedBorder)
                .font(DesignSystem.Typography.mono())
                .disabled(registry.broadcastIDs.isEmpty)
                .onSubmit(sendBroadcastCommand)
            Button("Send", action: sendBroadcastCommand)
                .disabled(registry.broadcastIDs.isEmpty || broadcastCommand.isEmpty)
        }
        .padding(.horizontal, DesignSystem.Spacing.medium)
        .padding(.vertical, 8)
    }

    private func sendBroadcastCommand() {
        guard !broadcastCommand.isEmpty, !registry.broadcastIDs.isEmpty else { return }
        registry.broadcast(Data((broadcastCommand + "\r").utf8))
        broadcastCommand = ""
    }
}
