import SwiftUI
import SSHoeboxCore
import CryptoKit

/// A tab-based terminal container shown inside HostDetailView.
/// Manages one or more SSH sessions to the same host.
struct TerminalTabView: View {
    @ObservedObject var themeManager = ThemeManager.shared
    let host: SavedHost
    let dbManager: DatabaseManager
    let vaultKey: SymmetricKey
    
    @StateObject private var viewModel: CredentialsViewModel
    @State private var sessions: [TerminalSession] = []
    @State private var selectedSessionId: UUID? = nil
    
    init(host: SavedHost, dbManager: DatabaseManager, vaultKey: SymmetricKey) {
        self.host = host
        self.dbManager = dbManager
        self.vaultKey = vaultKey
        _viewModel = StateObject(wrappedValue: CredentialsViewModel(dbManager: dbManager, vaultKey: vaultKey, hostId: host.id))
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Tab bar
            if !sessions.isEmpty {
                tabBar
                    .background(DesignSystem.Colors.background)
            }
            
            // Terminal content
            if sessions.isEmpty {
                emptyState
            } else if let id = selectedSessionId,
                      let session = sessions.first(where: { $0.id == id }) {
                RemoteTerminalView(session: session.manager)
                    .id(id) // Force view recreation on tab switch
            }
        }
        .onAppear {
            // Auto-open first session
            if sessions.isEmpty {
                openNewSession()
            }
        }
    }
    
    // MARK: - Tab Bar
    
    private var tabBar: some View {
        HStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(sessions) { session in
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
                openNewSession()
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
        let isSelected = selectedSessionId == session.id
        return HStack(spacing: 6) {
            // Status indicator
            Circle()
                .fill(statusColor(for: session.manager.connectionState))
                .frame(width: 6, height: 6)
            
            Text(session.title)
                .font(.system(size: 12))
                .foregroundStyle(isSelected ? DesignSystem.Colors.textPrimary : DesignSystem.Colors.textSecondary)
                .lineLimit(1)
            
            // Close button
            Button {
                closeSession(session)
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
            selectedSessionId = session.id
        }
    }
    
    private func statusColor(for state: SSHSessionManager.ConnectionState) -> Color {
        switch state {
        case .connected:   return .green
        case .connecting:  return .yellow
        case .disconnected: return .gray
        case .failed:      return .red
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
                openNewSession()
            }
            .buttonStyle(.borderedProminent)
            .tint(DesignSystem.Colors.accent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
    }
    
    // MARK: - Session Management
    
    private func openNewSession() {
        viewModel.fetchCredentials()
        
        let manager = SSHSessionManager()
        let sessionNumber = sessions.count + 1
        let session = TerminalSession(
            id: UUID(),
            title: "Terminal \(sessionNumber)",
            manager: manager
        )
        sessions.append(session)
        selectedSessionId = session.id
        
        // Connect using stored credentials
        Task {
            await connectSession(manager: manager)
        }
    }
    
    private func connectSession(manager: SSHSessionManager) async {
        let hostname = host.decryptedHostname(using: vaultKey)
        let user = host.decryptedUser(using: vaultKey)
        let port = host.port ?? 22
        
        // Find password credential
        if let cred = viewModel.credentials.first(where: { $0.type == "password" }) {
            if cred.isInteractive {
                // YubiKey / hardware token — interactive mode
                await manager.connectInteractive(host: hostname, port: port, username: user)
            } else if let password = viewModel.decrypt(credential: cred) {
                await manager.connect(host: hostname, port: port, username: user, password: password)
            }
        } else {
            // No password credential — try interactive
            await manager.connectInteractive(host: hostname, port: port, username: user)
        }
    }
    
    private func closeSession(_ session: TerminalSession) {
        session.manager.disconnect()
        sessions.removeAll { $0.id == session.id }
        if selectedSessionId == session.id {
            selectedSessionId = sessions.last?.id
        }
    }
}

// MARK: - Terminal Session Model

struct TerminalSession: Identifiable {
    let id: UUID
    let title: String
    let manager: SSHSessionManager
}
