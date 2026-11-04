import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SSHoeboxCore

/// The Login Log window: this app run's SSH/SFTP login diagnostics (see `LoginTrace`).
/// Shown only while the vault is unlocked, since the lines hold usernames and hostnames.
struct LoginLogView: View {
    @ObservedObject var viewModel: VaultViewModel
    @ObservedObject var store: LoginLogStore = .shared

    @State private var search = ""
    @State private var errorsOnly = false
    @State private var copied = false

    static let showCommand =
        #"/usr/bin/log show --last 1d --style compact --predicate 'subsystem == "com.sshoebox.app" AND category == "login"'"#

    private var visible: [LoginLogEntry] {
        store.visibleEntries(search: search, errorsOnly: errorsOnly)
    }

    var body: some View {
        Group {
            if viewModel.isUnlocked {
                logContent
            } else {
                lockedView
            }
        }
        .frame(minWidth: 640, minHeight: 360)
        .background(DesignSystem.Colors.background)
        .navigationTitle("Login Log")
    }

    // MARK: - Content

    private var logContent: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if visible.isEmpty {
                emptyView
            } else {
                lines
            }
            Divider()
            footer
        }
    }

    private var toolbar: some View {
        HStack(spacing: DesignSystem.Spacing.standard) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            TextField("Filter (host, user, error…)", text: $search)
                .textFieldStyle(.plain)
                .frame(minWidth: 160)

            if let attempt = store.focusedAttemptID {
                HStack(spacing: 4) {
                    Text("Attempt \(attempt)")
                        .font(DesignSystem.Typography.label().monospaced())
                    Button {
                        store.focusedAttemptID = nil
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .help("Show all attempts")
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(DesignSystem.Colors.accent.opacity(0.18))
                .clipShape(Capsule())
            }

            Spacer()

            Toggle("Errors only", isOn: $errorsOnly)
                .toggleStyle(.checkbox)

            Button(copied ? "Copied" : "Copy") { copyVisible() }
                .disabled(visible.isEmpty)
                .help("Copy the lines shown")
            Button("Save…") { saveVisible() }
                .disabled(visible.isEmpty)
                .help("Save the lines shown to a text file")
            Button("Clear") { store.clear() }
                .disabled(store.entries.isEmpty)
                .help("Clear the in-app log (the macOS log keeps its copy)")
        }
        .padding(.horizontal, DesignSystem.Spacing.medium)
        .padding(.vertical, DesignSystem.Spacing.standard)
        .background(DesignSystem.Colors.surface)
    }

    private var lines: some View {
        ScrollViewReader { proxy in
            ScrollView([.vertical, .horizontal]) {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(visible) { entry in
                        LoginLogRow(entry: entry, isFocused: store.focusedAttemptID != nil) { attempt in
                            store.focusedAttemptID = attempt
                        }
                        .id(entry.id)
                    }
                }
                .padding(DesignSystem.Spacing.standard)
                .textSelection(.enabled)
            }
            .onAppear { scrollToEnd(proxy) }
            .onChange(of: visible.last?.id) { scrollToEnd(proxy) }
        }
    }

    private func scrollToEnd(_ proxy: ScrollViewProxy) {
        if let last = visible.last { proxy.scrollTo(last.id, anchor: .bottom) }
    }

    private var emptyView: some View {
        VStack(spacing: DesignSystem.Spacing.standard) {
            Image(systemName: "text.magnifyingglass")
                .font(.system(size: 32))
                .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.6))
            Text(store.entries.isEmpty ? "No login attempts since SSHoebox started or the vault was unlocked."
                                       : "No lines match the filter.")
                .font(DesignSystem.Typography.body())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var footer: some View {
        HStack(spacing: DesignSystem.Spacing.standard) {
            Text("\(visible.count) of \(store.entries.count) lines · this app run. Earlier attempts are in the macOS log.")
                .font(DesignSystem.Typography.label())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            Spacer()
            Button("Copy Terminal Command") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(Self.showCommand, forType: .string)
            }
            .help(Self.showCommand)
            Button("Open Console") {
                if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Console") {
                    NSWorkspace.shared.openApplication(at: url, configuration: .init())
                }
            }
            .help("Filter on subsystem com.sshoebox.app")
        }
        .controlSize(.small)
        .padding(.horizontal, DesignSystem.Spacing.medium)
        .padding(.vertical, 6)
        .background(DesignSystem.Colors.surface)
    }

    private var lockedView: some View {
        VStack(spacing: DesignSystem.Spacing.medium) {
            Image(systemName: "lock.fill")
                .font(.system(size: 36))
                .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.6))
            Text("Unlock the vault to view the login log.")
                .font(DesignSystem.Typography.body())
                .foregroundStyle(DesignSystem.Colors.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Actions

    private func copyVisible() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(LoginLogStore.text(of: visible), forType: .string)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
    }

    private func saveVisible() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "SSHoebox Login Log.txt"
        let text = LoginLogStore.text(of: visible)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}

private struct LoginLogRow: View {
    let entry: LoginLogEntry
    let isFocused: Bool
    let onShowAttempt: (String) -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: DesignSystem.Spacing.standard) {
            Text(LoginLogStore.timestamp(entry.date).suffix(12))
                .foregroundStyle(DesignSystem.Colors.textSecondary)
            Text(entry.line)
                .foregroundStyle(entry.level == .error ? DesignSystem.Colors.error : DesignSystem.Colors.textPrimary)
                .fixedSize(horizontal: true, vertical: false)
        }
        .font(.system(size: 12, design: .monospaced))
        .contextMenu {
            if let attempt = entry.attemptID, !isFocused {
                Button("Show Only Attempt \(attempt)") { onShowAttempt(attempt) }
            }
            Button("Copy Line") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(LoginLogStore.text(of: [entry]), forType: .string)
            }
        }
    }
}

/// Opens the Login Log window, optionally showing only one attempt.
struct OpenLoginLogAction {
    let openWindow: OpenWindowAction

    @MainActor
    func callAsFunction(attemptID: String? = nil) {
        LoginLogStore.shared.focusedAttemptID = attemptID
        openWindow(id: LoginLogStore.windowID)
        NSApp.activate(ignoringOtherApps: true)
    }
}
