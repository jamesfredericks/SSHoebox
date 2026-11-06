import XCTest
import SwiftUI
import AppKit
import CryptoKit
import SSHoeboxCore
@testable import SSHoeboxApp

/// Renders the real views in an offscreen window against a throwaway vault, and walks the
/// new screens. A missing environment object or a crash in a view body fails here instead of
/// in the app. Nothing connects anywhere real: the hosts point at a closed local port.
@MainActor
final class UISmokeTests: XCTestCase {
    private var vaultDir: URL!
    private var window: NSWindow!

    override func setUp() async throws {
        vaultDir = FileManager.default.temporaryDirectory.appendingPathComponent("SSHoeboxUITests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        UserDefaults.standard.set(vaultDir.path, forKey: "vaultDirectoryRaw")
        UserDefaults.standard.set(false, forKey: "isAgentEnabled")
        UserDefaults.standard.set(0, forKey: SSHSessionOptions.keepAliveDefaultsKey)
    }

    override func tearDown() async throws {
        window?.close()
        window = nil
        UserDefaults.standard.removeObject(forKey: "vaultDirectoryRaw")
        UserDefaults.standard.removeObject(forKey: SSHSessionOptions.keepAliveDefaultsKey)
        try? FileManager.default.removeItem(at: vaultDir)
    }

    private func render(_ view: some View) async {
        if window == nil {
            window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800),
                              styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        }
        window.contentView = NSHostingView(rootView: view)
        await pump()
    }

    /// With SSHOEBOX_UI_SNAPSHOT_DIR set, saves what the window shows as `<name>.png`.
    private func snapshot(_ name: String) {
        guard let folder = ProcessInfo.processInfo.environment["SSHOEBOX_UI_SNAPSHOT_DIR"],
              let view = window.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?
            .write(to: URL(fileURLWithPath: folder).appendingPathComponent("\(name).png"))
    }

    /// Lets SwiftUI and AppKit lay out and run pending updates.
    /// Awaits in small steps, so tasks queued on the main actor (connects, state changes) run.
    private func pump(_ seconds: TimeInterval = 0.3) async {
        let end = Date().addingTimeInterval(seconds)
        repeat {
            window.contentView?.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.02))
            try? await Task.sleep(nanoseconds: 20_000_000)
        } while Date() < end
        window.contentView?.layoutSubtreeIfNeeded()
    }

    func testMainScreensRender() async throws {
        let vault = VaultViewModel()
        vault.createVault(password: "correct horse battery staple")
        for _ in 0..<300 where vault.isUnlocking { try await Task.sleep(nanoseconds: 20_000_000) }
        let (db, key) = try XCTUnwrap(vault.getDependencies())

        var bastion = try SavedHost.encrypted(name: "bastion", hostname: "127.0.0.1", port: 1, protocolType: "ssh",
                                              user: "me", groupId: nil, using: key)
        try bastion.setOptions(HostOptions(tags: ["edge"], isFavorite: true), using: key)
        var app = try SavedHost.encrypted(name: "app", hostname: "127.0.0.1", port: 1, protocolType: "ssh",
                                          user: "me", groupId: nil, using: key)
        try app.setOptions(HostOptions(jumpHostId: bastion.id,
                                       portForwards: [PortForward(localPort: 18080, remoteHost: "web", remotePort: 80)],
                                       startupCommand: "uptime", tags: ["prod", "web"]), using: key)
        try HostRepository(dbManager: db).save(bastion)
        try HostRepository(dbManager: db).save(app)
        try SnippetRepository(dbManager: db).save(hostId: nil, name: "Disk", command: "df -h", vaultKey: key)

        let registry = TerminalSessionRegistry()
        let navigator = AppNavigator()
        await render(MainView(viewModel: vault).environmentObject(registry).environmentObject(navigator))

        // Host list with favorites and tags, then a host, its terminal and its files.
        snapshot("1-hosts")
        navigator.open(hostId: app.id, action: .show)
        await pump()
        navigator.open(hostId: app.id, action: .terminal)
        await pump(1.0)
        let store = try XCTUnwrap(registry.existingStore(for: app.id))
        XCTAssertEqual(store.sessions.count, 1, "the terminal action opened a session")
        navigator.open(hostId: app.id, action: .newTerminal)
        await pump(0.5)
        XCTAssertEqual(store.sessions.count, 2)
        snapshot("2-terminal")
        guard case .failed(let reason) = store.sessions[0].manager.connectionState else {
            return XCTFail("connecting to a closed port should fail, not \(store.sessions[0].manager.connectionState)")
        }
        XCTAssertTrue(reason.contains("Jump host 1"), "the failing jump host is named: \(reason)")
        store.isSplit = true
        await pump()
        registry.setBroadcast(true, for: store.sessions)
        await pump(1.0)
        snapshot("3-split-broadcast")
        XCTAssertEqual(store.snippets().map(\.name), ["Disk"])
        store.sessions[0].sendCommand("echo hi")

        // The session's terminal view is hosted in the window.
        XCTAssertNotNil(store.sessions[0].terminal.view.window, "terminal view is on screen")

        // Same sessions in the workspace; the view moves there.
        navigator.sidebar = .sessions
        await pump()
        snapshot("4-workspace")
        XCTAssertNotNil(store.sessions[1].terminal.view.window)

        navigator.open(hostId: app.id, action: .files)
        await pump(1.0)
        snapshot("5-files")

        UserDefaults.standard.set(vaultDir.appendingPathComponent("recordings").path,
                                  forKey: SessionRecording.directoryDefaultsKey)
        defer { UserDefaults.standard.removeObject(forKey: SessionRecording.directoryDefaultsKey) }
        let recorder = try SessionRecorder(hostName: "app", endpoint: "me@127.0.0.1:1", vaultKey: key)
        recorder.record(Data("uptime\r\n 12:00 up 3 days\r\n".utf8))
        recorder.finish()
        for item in [MainView.SidebarItem.preferences, .logs, .generator, .recordings, .hosts] {
            navigator.sidebar = item
            await pump()
        }

        await render(RecordingsView(vaultKey: key).environmentObject(registry))
        snapshot("10-recordings")
        await render(RecordingsView(vaultKey: key, selecting: recorder.fileURL).environmentObject(registry))
        snapshot("11-recording-open")

        // Sheets and palettes on their own.
        await render(QuickConnectView(dbManager: db, vaultKey: key).environmentObject(navigator))
        snapshot("6-quick-connect")
        await render(Form { HostOptionsSections(options: .constant(app.decryptedOptions(using: key)),
                                          jumpCandidates: [(bastion.id, "bastion")]) }.formStyle(.grouped))
        snapshot("7-host-options")
        await render(ManageSnippetsSheet(dbManager: db, vaultKey: key, hostId: app.id, hostName: "app"))
        snapshot("8-snippets")
        let line = try AuthorizedKeys.publicKeyLine(fromPEM: TestKeysForApp.ed25519)
        await render(InstallKeySheet(publicKeyLine: line, keyName: "this key", initialHostId: app.id,
                               dbManager: db, vaultKey: key).environmentObject(registry))
        snapshot("9-install-key")

        registry.removeAll()
        vault.lock()
    }
}

/// The real path: terminal output through a session into its recording, read while it's
/// still going (as the Recordings view does) and after it stops.
@MainActor
final class SessionRecordingPathTests: XCTestCase {
    func testOutputReachesTheRecordingWhileItRunsAndAfter() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("SSHoeboxRec-\(UUID().uuidString)")
        UserDefaults.standard.set(folder.path, forKey: SessionRecording.directoryDefaultsKey)
        defer {
            UserDefaults.standard.removeObject(forKey: SessionRecording.directoryDefaultsKey)
            try? FileManager.default.removeItem(at: folder)
        }
        let key = SymmetricKey(size: .bits256)
        let manager = SSHSessionManager()
        let session = TerminalSession(hostId: "h", hostName: "web-01", title: "Terminal 1", manager: manager, vaultKey: key)
        session.startRecording()
        let url = try XCTUnwrap(session.recorder?.fileURL)

        // As the SSH session delivers output: a command, its result, and a waiting prompt.
        manager.onOutput?(Data("\u{1B}[1mdeploy@web-01\u{1B}[0m:~$ uptime\r\n 14:33 up 9 days\r\ndeploy@web-01:~$ ".utf8))

        // The flush timer seals it within a couple of seconds, prompt line included.
        for _ in 0..<40 where (try? SessionRecordingReader.read(url, vaultKey: key))?.text.isEmpty ?? true {
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        let live = try SessionRecordingReader.read(url, vaultKey: key)
        XCTAssertEqual(live.status, .unfinished)
        XCTAssertEqual(live.text, "deploy@web-01:~$ uptime\n 14:33 up 9 days\ndeploy@web-01:~$ ")

        manager.onOutput?(Data("exit\r\n".utf8))
        session.stopRecording()
        let done = try SessionRecordingReader.read(url, vaultKey: key)
        XCTAssertEqual(done.status, .complete)
        XCTAssertEqual(done.text, "deploy@web-01:~$ uptime\n 14:33 up 9 days\ndeploy@web-01:~$ exit\n")
        XCTAssertEqual(done.metadata.hostName, "web-01")
    }
}

enum TestKeysForApp {
    /// A throwaway key generated for this test.
    static let ed25519 = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACAe2lBJV7LMbghypzCWCdutmVzBcbMwaDMb0cZEBuPfyAAAAJBkvcwLZL3M
    CwAAAAtzc2gtZWQyNTUxOQAAACAe2lBJV7LMbghypzCWCdutmVzBcbMwaDMb0cZEBuPfyA
    AAAEASUxlt7UbSRJuiWqAQeG1cV6vrYCfJPCz0J8uMpJQwRB7aUElXssxuCHKnMJYJ262Z
    XMFxszBoMxvRxkQG49/IAAAABnVpdGVzdAECAwQFBgc=
    -----END OPENSSH PRIVATE KEY-----
    """
}
