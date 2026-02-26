import SwiftUI
import SSHoeboxCore
import CryptoKit

/// A tab-based terminal container shown inside HostDetailView.
/// Sessions are owned by TerminalSessionStore (a @StateObject on HostDetailView)
/// so they survive tab switches and other view updates.
struct TerminalTabView: View {
    @ObservedObject var store: TerminalSessionStore
    @ObservedObject var themeManager = ThemeManager.shared

    var body: some View {
        VStack(spacing: 0) {
            // Tab bar — only shown when at least one session exists
            if !store.sessions.isEmpty {
                tabBar
                    .background(DesignSystem.Colors.background)
            }

            // Terminal content
            if store.sessions.isEmpty {
                emptyState
            } else {
                // Render ALL sessions, show only the selected one.
                // Using ZStack + opacity keeps every NSView alive so no session is torn down.
                ZStack {
                    ForEach(store.sessions) { session in
                        RemoteTerminalView(session: session.manager)
                            .opacity(store.selectedSessionId == session.id ? 1 : 0)
                    }
                }
            }
        }
        .onAppear {
            // Auto-open first session only if none exist yet
            if store.sessions.isEmpty {
                store.openNewSession()
            }
        }
    }

    // MARK: - Tab Bar

    private var tabBar: some View {
        HStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(store.sessions) { session in
                        tabButton(for: session)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            }

            Divider()
                .frame(height: 20)

            // New tab button
            Button {
                store.openNewSession()
            } label: {
                Image(systemName: "plus")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 6)
        }
        .frame(height: 36)
        .overlay(alignment: .bottom) {
            Divider()
        }
    }

    private func tabButton(for session: TerminalSession) -> some View {
        let isSelected = store.selectedSessionId == session.id
        return HStack(spacing: 6) {
            // Connection status indicator
            Circle()
                .fill(statusColor(for: session.manager.connectionState))
                .frame(width: 6, height: 6)

            Text(session.title)
                .font(.system(size: 12))
                .foregroundStyle(isSelected ? DesignSystem.Colors.textPrimary : DesignSystem.Colors.textSecondary)
                .lineLimit(1)

            // Close button
            Button {
                store.closeSession(session)
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 9, weight: .medium))
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(isSelected ? DesignSystem.Colors.surface : Color.clear)
        )
        .onTapGesture {
            store.select(session)
        }
    }

    private func statusColor(for state: SSHSessionManager.ConnectionState) -> Color {
        switch state {
        case .connected:    return .green
        case .connecting:   return .yellow
        case .disconnected: return .gray
        case .failed:       return .red
        }
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "terminal")
                .font(.system(size: 48))
                .foregroundStyle(DesignSystem.Colors.accent.opacity(0.6))
            Text("No active sessions")
                .font(.title3)
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            Button("Open Terminal") {
                store.openNewSession()
            }
            .buttonStyle(.borderedProminent)
            .tint(DesignSystem.Colors.accent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
    }
}
