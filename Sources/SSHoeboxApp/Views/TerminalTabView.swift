import SwiftUI
import SSHoeboxCore
import CryptoKit

/// A host's terminal sessions, as tabs or side by side, shown inside HostDetailView.
/// Sessions are owned by TerminalSessionStore (held by TerminalSessionRegistry)
/// so they survive tab switches and other view updates.
/// This view never opens a session by itself: HostDetailView keeps it rendered
/// while hidden, so connecting is left to an explicit user action.
struct TerminalTabView: View {
    @ObservedObject var store: TerminalSessionStore
    @ObservedObject var themeManager = ThemeManager.shared
    @EnvironmentObject private var registry: TerminalSessionRegistry
    @State private var showingSnippets = false

    private var selected: TerminalSession? {
        store.sessions.first { $0.id == store.selectedSessionId }
    }

    var body: some View {
        VStack(spacing: 0) {
            if !store.sessions.isEmpty {
                tabBar
                    .background(DesignSystem.Colors.background)
            }

            if store.sessions.isEmpty {
                emptyState
            } else if store.isSplit && store.sessions.count > 1 {
                SessionGrid(sessions: store.sessions, selectedId: store.selectedSessionId, showHostName: false) { session in
                    store.select(session)
                }
            } else {
                // Render ALL sessions, show only the selected one.
                // Using ZStack + opacity keeps every terminal alive and laid out.
                ZStack {
                    ForEach(store.sessions) { session in
                        let isSelected = store.selectedSessionId == session.id
                        SessionTerminalHost(session: session, focused: isSelected)
                            .opacity(isSelected ? 1 : 0)
                            .allowsHitTesting(isSelected)
                    }
                    if let selected {
                        SessionStateOverlay(manager: selected.manager) {
                            store.reconnect(selected)
                        } onPassphrase: { passphrase in
                            store.submitPassphrase(passphrase, for: selected)
                        }
                    }
                }
                .overlay(alignment: .top) {
                    if let selected, registry.isBroadcasting(selected) {
                        BroadcastBanner(count: registry.broadcastIDs.count)
                    }
                }
            }
        }
        .sheet(isPresented: $showingSnippets) {
            ManageSnippetsSheet(dbManager: store.snippetContext.dbManager, vaultKey: store.snippetContext.vaultKey,
                                hostId: store.host.id, hostName: store.host.decryptedName(using: store.snippetContext.vaultKey))
        }
    }

    // MARK: - Tab Bar

    private var tabBar: some View {
        HStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(store.sessions) { session in
                        SessionTabButton(session: session, isSelected: store.selectedSessionId == session.id,
                                         isBroadcasting: registry.isBroadcasting(session)) {
                            store.select(session)
                        } onClose: {
                            store.closeSession(session)
                        }
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            }

            Divider().frame(height: 20)

            HStack(spacing: 2) {
                snippetsMenu
                if let selected {
                    TunnelsMenu(manager: selected.manager)
                    RecordButton(session: selected)
                }
                broadcastButton
                Button {
                    store.isSplit.toggle()
                } label: {
                    Image(systemName: store.isSplit ? "rectangle.split.2x1.fill" : "rectangle.split.2x1")
                        .frame(width: 26, height: 28)
                }
                .buttonStyle(.plain)
                .foregroundStyle(store.isSplit ? DesignSystem.Colors.accent : DesignSystem.Colors.textSecondary)
                .disabled(store.sessions.count < 2)
                .help(store.isSplit ? "Show one session at a time" : "Show this host's sessions side by side")
            }
            .padding(.horizontal, 4)

            Divider().frame(height: 20)

            // Font size controls
            HStack(spacing: 0) {
                Button {
                    themeManager.decreaseFontSize()
                } label: {
                    Image(systemName: "minus")
                        .font(.system(size: 11, weight: .medium))
                        .frame(width: 24, height: 28)
                }
                .buttonStyle(.plain)
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .help("Decrease font size (⌘-)")

                Button {
                    themeManager.increaseFontSize()
                } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 11, weight: .medium))
                        .frame(width: 24, height: 28)
                }
                .buttonStyle(.plain)
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .help("Increase font size (⌘+)")
            }
            .padding(.horizontal, 4)

            Divider().frame(height: 20)

            // New tab button
            Button {
                store.openNewSession()
            } label: {
                Image(systemName: "plus.rectangle")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 6)
            .help("New terminal tab")
        }
        .frame(height: 36)
        .overlay(alignment: .bottom) {
            Divider()
        }
    }

    private var snippetsMenu: some View {
        let snippets = store.snippets()
        return Menu {
            if snippets.isEmpty {
                Text("No snippets yet")
            }
            ForEach(snippets, id: \.id) { snippet in
                Button(snippet.isGlobal ? snippet.name : "\(snippet.name)  (this host)") {
                    // ⌥-click types the command without pressing Return.
                    let run = !NSEvent.modifierFlags.contains(.option)
                    selected?.sendCommand(snippet.command, run: run)
                }
            }
            Divider()
            Button("Manage Snippets…") { showingSnippets = true }
        } label: {
            Image(systemName: "text.badge.plus")
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .frame(width: 28, height: 28)
        .help("Snippets: click to run in the current session, ⌥-click to type without running")
    }

    private var broadcastButton: some View {
        let all = store.sessions
        let allOn = !all.isEmpty && all.allSatisfy(registry.isBroadcasting)
        return Button {
            registry.setBroadcast(!allOn, for: all)
        } label: {
            Image(systemName: allOn ? "dot.radiowaves.left.and.right" : "dot.radiowaves.right")
                .frame(width: 26, height: 28)
        }
        .buttonStyle(.plain)
        .foregroundStyle(allOn ? Color.orange : DesignSystem.Colors.textSecondary)
        .help(allOn ? "Stop broadcasting to this host's sessions"
                    : "Broadcast: what you type in one of this host's sessions goes to all of them")
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

// MARK: - Tab Button

private struct SessionTabButton: View {
    @ObservedObject var session: TerminalSession
    @ObservedObject private var manager: SSHSessionManager
    let isSelected: Bool
    let isBroadcasting: Bool
    let onSelect: () -> Void
    let onClose: () -> Void

    init(session: TerminalSession, isSelected: Bool, isBroadcasting: Bool,
         onSelect: @escaping () -> Void, onClose: @escaping () -> Void) {
        self.session = session
        self.manager = session.manager
        self.isSelected = isSelected
        self.isBroadcasting = isBroadcasting
        self.onSelect = onSelect
        self.onClose = onClose
    }

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(SessionStatus.color(for: manager.connectionState))
                .frame(width: 6, height: 6)
            Text(session.title)
                .font(.system(size: 12))
                .foregroundStyle(isSelected ? DesignSystem.Colors.textPrimary : DesignSystem.Colors.textSecondary)
                .lineLimit(1)
            if session.isRecording {
                Image(systemName: "record.circle")
                    .font(.system(size: 9))
                    .foregroundStyle(.red)
                    .help("Recording (encrypted)")
            }
            if isBroadcasting {
                Image(systemName: "dot.radiowaves.left.and.right")
                    .font(.system(size: 9))
                    .foregroundStyle(.orange)
                    .help("In the broadcast group")
            }
            Button(action: onClose) {
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
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
    }
}

enum SessionStatus {
    static func color(for state: SSHSessionManager.ConnectionState) -> Color {
        switch state {
        case .connected:    return .green
        case .connecting:   return .yellow
        case .disconnected: return .gray
        case .failed:       return .red
        }
    }
}

// MARK: - Tunnels and Recording

/// The session's port forwards, each with its state; click one to start or stop it.
struct TunnelsMenu: View {
    @ObservedObject var manager: SSHSessionManager

    var body: some View {
        if !manager.forwards.isEmpty {
            let listening = manager.forwards.filter { $0.state == .listening }.count
            Menu {
                ForEach(manager.forwards) { status in
                    Button {
                        if status.state == .listening {
                            manager.stopForward(id: status.id)
                        } else {
                            Task { await manager.startForward(id: status.id) }
                        }
                    } label: {
                        switch status.state {
                        case .listening: Label("\(status.forward.summary) — open (click to stop)", systemImage: "checkmark.circle.fill")
                        case .stopped: Label("\(status.forward.summary) — stopped (click to start)", systemImage: "circle")
                        case .failed(let reason): Label("\(status.forward.summary) — \(reason)", systemImage: "exclamationmark.triangle")
                        }
                    }
                    .disabled(manager.connectionState != .connected)
                }
            } label: {
                Image(systemName: "point.3.connected.trianglepath.dotted")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .frame(width: 28, height: 28)
            .foregroundStyle(listening > 0 ? Color.green : DesignSystem.Colors.textSecondary)
            .help("Tunnels: \(listening) of \(manager.forwards.count) open")
        }
    }
}

/// Starts or stops recording the session's output (encrypted, see `SessionRecorder`).
struct RecordButton: View {
    @ObservedObject var session: TerminalSession
    @EnvironmentObject private var navigator: AppNavigator

    var body: some View {
        Menu {
            if session.isRecording {
                Text("Recording (encrypted)")
                Button("Stop Recording") { session.stopRecording() }
            } else {
                Button("Start Recording") { session.startRecording() }
                if let error = session.recordingError {
                    Text("Couldn't record: \(error)")
                }
            }
            Button("Show Recordings") { navigator.sidebar = .recordings }
        } label: {
            Image(systemName: session.isRecording ? "record.circle.fill" : "record.circle")
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .frame(width: 28, height: 28)
        .foregroundStyle(session.isRecording ? Color.red : DesignSystem.Colors.textSecondary)
        .help(session.isRecording ? "Recording this session's output (encrypted)" : "Record this session's output, encrypted")
    }
}

/// Reminds that typing goes to several sessions.
struct BroadcastBanner: View {
    let count: Int

    var body: some View {
        Label("Broadcasting input to \(count) session\(count == 1 ? "" : "s")", systemImage: "dot.radiowaves.left.and.right")
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Capsule().fill(Color.orange.opacity(0.9)))
            .foregroundStyle(.black)
            .padding(.top, 6)
            .allowsHitTesting(false)
    }
}

// MARK: - Grid of Sessions

/// Sessions side by side, each with a header. Used for a host's split view and for the
/// Sessions workspace (all hosts).
struct SessionGrid: View {
    let sessions: [TerminalSession]
    let selectedId: UUID?
    let showHostName: Bool
    let onSelect: (TerminalSession) -> Void

    var body: some View {
        let columns = max(1, Int(Double(sessions.count).squareRoot().rounded(.up)))
        let rows = max(1, Int((Double(sessions.count) / Double(columns)).rounded(.up)))
        GeometryReader { geometry in
            let spacing: CGFloat = 4
            let width = max(0, (geometry.size.width - spacing * CGFloat(columns - 1)) / CGFloat(columns))
            let height = max(0, (geometry.size.height - spacing * CGFloat(rows - 1)) / CGFloat(rows))
            VStack(spacing: spacing) {
                ForEach(0..<rows, id: \.self) { row in
                    HStack(spacing: spacing) {
                        ForEach(0..<columns, id: \.self) { column in
                            let index = row * columns + column
                            if index < sessions.count {
                                SessionTile(session: sessions[index], isSelected: sessions[index].id == selectedId,
                                            showHostName: showHostName) {
                                    onSelect(sessions[index])
                                }
                                .frame(width: width, height: height)
                            } else {
                                Color.clear.frame(width: width, height: height)
                            }
                        }
                    }
                }
            }
        }
        .padding(4)
        .background(Color.black.opacity(0.4))
    }
}

/// One session in a grid: header (host, title, state, broadcast, record, close) and terminal.
struct SessionTile: View {
    @ObservedObject var session: TerminalSession
    @ObservedObject private var manager: SSHSessionManager
    @EnvironmentObject private var registry: TerminalSessionRegistry
    let isSelected: Bool
    let showHostName: Bool
    let onSelect: () -> Void

    init(session: TerminalSession, isSelected: Bool, showHostName: Bool, onSelect: @escaping () -> Void) {
        self.session = session
        self.manager = session.manager
        self.isSelected = isSelected
        self.showHostName = showHostName
        self.onSelect = onSelect
    }

    var body: some View {
        let broadcasting = registry.isBroadcasting(session)
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Circle()
                    .fill(SessionStatus.color(for: manager.connectionState))
                    .frame(width: 6, height: 6)
                Text(showHostName ? "\(session.hostName) — \(session.title)" : session.title)
                    .font(.system(size: 11, weight: isSelected ? .semibold : .regular))
                    .lineLimit(1)
                if session.isRecording {
                    Image(systemName: "record.circle").font(.system(size: 9)).foregroundStyle(.red)
                }
                Spacer()
                Toggle(isOn: Binding(get: { broadcasting },
                                     set: { registry.setBroadcast($0, for: [session]) })) {
                    Image(systemName: "dot.radiowaves.left.and.right")
                }
                .toggleStyle(.button)
                .controlSize(.mini)
                .tint(.orange)
                .help("Include this session in the broadcast group")
                Button {
                    registry.existingStore(for: session.hostId)?.closeSession(session)
                } label: {
                    Image(systemName: "xmark").font(.system(size: 9, weight: .medium))
                }
                .buttonStyle(.plain)
                .help("Close this session")
            }
            .foregroundStyle(isSelected ? DesignSystem.Colors.textPrimary : DesignSystem.Colors.textSecondary)
            .padding(.horizontal, 8)
            .frame(height: 24)
            .background(isSelected ? DesignSystem.Colors.surface : DesignSystem.Colors.background)
            .contentShape(Rectangle())
            .onTapGesture(perform: onSelect)

            ZStack {
                SessionTerminalHost(session: session, focused: isSelected)
                SessionStateOverlay(manager: manager) {
                    registry.existingStore(for: session.hostId)?.reconnect(session)
                } onPassphrase: { passphrase in
                    registry.existingStore(for: session.hostId)?.submitPassphrase(passphrase, for: session)
                }
            }
        }
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .stroke(broadcasting ? Color.orange : (isSelected ? DesignSystem.Colors.accent : DesignSystem.Colors.border),
                        lineWidth: broadcasting || isSelected ? 2 : 1)
                .allowsHitTesting(false)
        )
        .simultaneousGesture(TapGesture().onEnded(onSelect))
    }
}

// MARK: - Session State Overlay

/// Shown over the terminal when a session is disconnected, failed, or needs a key passphrase.
/// Observes the manager directly so it reacts to connection state changes.
struct SessionStateOverlay: View {
    @ObservedObject var manager: SSHSessionManager
    let onReconnect: () -> Void
    let onPassphrase: (String) -> Void

    @Environment(\.openWindow) private var openWindow
    @State private var passphraseInput = ""

    var body: some View {
        if manager.passphraseChallenge != nil {
            passphraseView
        } else {
            switch manager.connectionState {
            case .disconnected, .failed:
                disconnectedView
            default:
                EmptyView()
            }
        }
    }

    private var disconnectedView: some View {
        VStack(spacing: 16) {
            Image(systemName: "wifi.slash")
                .font(.system(size: 40))
                .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.6))
            Text("Session ended")
                .font(.title3)
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            if case .failed(let reason) = manager.connectionState {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .multilineTextAlignment(.center)
                    .lineLimit(4)
                    .frame(maxWidth: 420)
            }
            HStack(spacing: 12) {
                Button("View Login Log") {
                    OpenLoginLogAction(openWindow: openWindow)(attemptID: manager.lastLoginAttemptID)
                }
                .help("Show what happened during this login")
                Button("Reconnect") { onReconnect() }
                    .buttonStyle(.borderedProminent)
                    .tint(DesignSystem.Colors.accent)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08).opacity(0.92))
    }

    private var passphraseView: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.fill")
                .font(.system(size: 40))
                .foregroundStyle(DesignSystem.Colors.accent)
            Text("Key Passphrase Required")
                .font(.title3)
                .foregroundStyle(DesignSystem.Colors.textPrimary)
            Text("The private key for \(manager.passphraseChallenge?.keyOwner.endpoint ?? "this host") is encrypted. Enter the passphrase to continue.")
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
                .multilineTextAlignment(.center)
            SecureField("Passphrase", text: $passphraseInput)
                .textFieldStyle(.roundedBorder)
                .frame(width: 260)
                .onSubmit { submitPassphrase() }
            HStack(spacing: 12) {
                Button("Cancel") {
                    manager.passphraseChallenge = nil
                    passphraseInput = ""
                }
                .buttonStyle(.plain)
                .foregroundStyle(DesignSystem.Colors.textSecondary)

                Button("Unlock") { submitPassphrase() }
                    .buttonStyle(.borderedProminent)
                    .tint(DesignSystem.Colors.accent)
                    .disabled(passphraseInput.isEmpty)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
    }

    private func submitPassphrase() {
        guard !passphraseInput.isEmpty else { return }
        let p = passphraseInput
        passphraseInput = ""
        onPassphrase(p)
    }
}
