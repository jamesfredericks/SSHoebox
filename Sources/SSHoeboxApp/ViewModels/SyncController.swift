import Foundation
import AppKit
import CryptoKit
import SystemConfiguration
import SSHoeboxCore

extension Notification.Name {
    /// Posted after a sync changed the vault's hosts, credentials or trusted keys.
    static let vaultDidSync = Notification.Name("com.sshoebox.vaultDidSync")
    /// Posted after a sync applied settings changed on another Mac.
    static let syncedSettingsDidChange = Notification.Name("com.sshoebox.syncedSettingsDidChange")
}

/// The app settings that sync between Macs. Ones that only make sense on this Mac (vault
/// location, backup folder, the sync folder itself, Touch ID) don't.
@MainActor
enum SyncedSettings {
    enum Kind { case string, int, double, bool }

    static let all: [String: Kind] = [
        "selectedThemeId": .string,
        "terminalFontSize": .double,
        "autoLockTimeout": .int,
        VaultViewModel.deferAutoLockForSessionsKey: .bool,
        "clipboardClearTimeout": .int,
        "terminalAllowOSC52": .bool,
        "isAgentEnabled": .bool,
    ]

    /// This Mac's values. Settings it has never stored are left out.
    static func current() -> [String: SyncedValue] {
        let defaults = UserDefaults.standard
        var values: [String: SyncedValue] = [:]
        for (key, kind) in all where defaults.object(forKey: key) != nil {
            switch kind {
            case .string: values[key] = defaults.string(forKey: key).map(SyncedValue.string)
            case .int: values[key] = .int(defaults.integer(forKey: key))
            case .double: values[key] = .double(defaults.double(forKey: key))
            case .bool: values[key] = .bool(defaults.bool(forKey: key))
            }
        }
        return values
    }

    /// Stores a synced value, ignoring one of the wrong type for its key.
    static func store(_ value: SyncedValue, forKey key: String) {
        let defaults = UserDefaults.standard
        switch (all[key], value) {
        case (.string, .string(let v)): defaults.set(v, forKey: key)
        case (.int, .int(let v)): defaults.set(v, forKey: key)
        case (.double, .double(let v)): defaults.set(v, forKey: key)
        case (.bool, .bool(let v)): defaults.set(v, forKey: key)
        default: break
        }
    }
}

/// Runs vault sync (see `VaultSyncEngine`) while the vault is unlocked: on unlock, shortly
/// after each change to the vault or a synced setting, when another Mac's file changes, when
/// the app becomes active, and every minute in case a change went unnoticed.
@MainActor
final class SyncController: ObservableObject {
    static let folderKey = "syncFolderPath"
    static let deviceIDKey = "syncDeviceID"
    /// The synced settings as of the last sync, with when each last changed.
    static let settingStampsKey = "syncSettingStamps"
    /// Set by a restore: the next sync makes this Mac's data replace the other Macs'.
    static let newEpochPendingKey = "syncNewEpochPending"

    @Published private(set) var folderURL: URL? = UserDefaults.standard.string(forKey: folderKey).map { URL(fileURLWithPath: $0) }
    @Published private(set) var isSyncing = false
    @Published private(set) var lastSyncedAt: Date?
    @Published private(set) var lastError: String?
    @Published private(set) var otherDevices: [SyncedDevice] = []

    var isEnabled: Bool { folderURL != nil }

    /// Applies settings that changed on another Mac. Provided by VaultViewModel.
    var applySettings: (([String: SyncedValue]) -> Void)?

    private struct Session {
        let dbManager: DatabaseManager
        let vaultKey: SymmetricKey
        let vaultMetadata: Data
    }
    private var session: Session?

    private var databaseObservation: SyncChangeObservation?
    private var folderWatcher: DispatchSourceFileSystemObject?
    private var pollTimer: Timer?
    private var notificationObservers: [NSObjectProtocol] = []
    private var pendingSync: Task<Void, Never>?
    private var needsAnotherPass = false

    private let deviceID: String = {
        if let id = UserDefaults.standard.string(forKey: SyncController.deviceIDKey) { return id }
        let id = UUID().uuidString
        UserDefaults.standard.set(id, forKey: SyncController.deviceIDKey)
        return id
    }()
    private let deviceName = (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? "Mac"

    // MARK: - Vault lifecycle

    func start(dbManager: DatabaseManager, vaultKey: SymmetricKey, vaultMetadata: Data) {
        session = Session(dbManager: dbManager, vaultKey: vaultKey, vaultMetadata: vaultMetadata)
        startWatching()
        syncNow()
    }

    func stop() {
        session = nil
        stopWatching()
        pendingSync?.cancel()
        pendingSync = nil
        needsAnotherPass = false
    }

    // MARK: - Folder

    /// Starts syncing through `chosen`, or the folder within it that `resolveFolder` picks.
    func enable(_ chosen: URL, vaultDirectory: URL) throws {
        let folder = try VaultSyncEngine.resolveFolder(chosen)
        guard folder.standardizedFileURL.resolvingSymlinksInPath()
                != vaultDirectory.standardizedFileURL.resolvingSymlinksInPath() else {
            throw SyncSetupError.vaultFolder
        }
        if let session,
           let existing = try VaultSyncEngine.vaultMetadata(in: folder),
           let own = try? JSONDecoder().decode(VaultMetadata.self, from: session.vaultMetadata),
           existing.metadata.identifier != own.identifier {
            throw VaultSyncError.differentVault
        }
        setFolder(folder)
    }

    /// Changes the sync folder (nil stops syncing). The files already in a folder are left there.
    func setFolder(_ folder: URL?) {
        folderURL = folder
        UserDefaults.standard.set(folder?.path, forKey: Self.folderKey)
        // Take the settings already synced through the new folder before sharing this Mac's.
        UserDefaults.standard.removeObject(forKey: Self.settingStampsKey)
        UserDefaults.standard.removeObject(forKey: Self.newEpochPendingKey)
        lastSyncedAt = nil
        lastError = nil
        otherDevices = []
        if folder == nil {
            stopWatching()
        } else {
            startWatching()
            syncNow()
        }
    }

    // MARK: - Syncing

    func scheduleSync() {
        guard session != nil, folderURL != nil else { return }
        pendingSync?.cancel()
        pendingSync = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.5))
            guard !Task.isCancelled else { return }
            self?.syncNow()
        }
    }

    func syncNow() {
        guard let session, let folderURL else { return }
        guard !isSyncing else {
            needsAnotherPass = true
            return
        }
        isSyncing = true

        let baseline = loadStamps()
        // On the first sync with a folder this Mac only takes settings; it shares its own on the next pass.
        let settings = baseline.map(stampedSettings) ?? [:]
        let startNewEpoch = UserDefaults.standard.bool(forKey: Self.newEpochPendingKey)
        let deviceID = deviceID
        let deviceName = deviceName

        Task {
            let outcome = await Task.detached(priority: .utility) {
                Result {
                    try VaultSyncEngine(
                        dbManager: session.dbManager, vaultKey: session.vaultKey, vaultMetadata: session.vaultMetadata,
                        folder: folderURL, deviceID: deviceID, deviceName: deviceName
                    ).sync(settings: settings, startNewEpoch: startNewEpoch)
                }
            }.value
            isSyncing = false
            // The folder was changed or sync stopped meanwhile.
            guard self.folderURL == folderURL else { return }

            switch outcome {
            case .success(let result):
                if startNewEpoch { UserDefaults.standard.removeObject(forKey: Self.newEpochPendingKey) }
                lastSyncedAt = Date()
                otherDevices = result.otherDevices
                lastError = result.unreadableFiles == 0 ? nil
                    : "\(result.unreadableFiles) file(s) in the sync folder couldn't be read. They may be damaged, or from a vault with the same ID but a different key."
                applyMerged(result.settings)
                if result.changedLocalData {
                    NotificationCenter.default.post(name: .vaultDidSync, object: nil)
                }
                if baseline == nil { needsAnotherPass = true }
            case .failure(let error):
                lastError = error.localizedDescription
            }
            if needsAnotherPass {
                needsAnotherPass = false
                syncNow()
            }
        }
    }

    // MARK: - Settings

    private func loadStamps() -> [String: StampedSetting]? {
        guard let data = UserDefaults.standard.data(forKey: Self.settingStampsKey) else { return nil }
        return try? JSONDecoder().decode([String: StampedSetting].self, from: data)
    }

    /// This Mac's settings, stamped with when they changed: a value that differs from the
    /// last sync changed now.
    private func stampedSettings(baseline: [String: StampedSetting]) -> [String: StampedSetting] {
        let now = Date()
        return SyncedSettings.current().reduce(into: [:]) { result, entry in
            if let known = baseline[entry.key], known.value == entry.value {
                result[entry.key] = known
            } else {
                result[entry.key] = StampedSetting(value: entry.value, modifiedAt: now)
            }
        }
    }

    private func applyMerged(_ merged: [String: StampedSetting]) {
        // Saved first, so the defaults writes below don't look like local changes.
        UserDefaults.standard.set(try? JSONEncoder().encode(merged), forKey: Self.settingStampsKey)
        let current = SyncedSettings.current()
        let changed = merged.filter { current[$0.key] != $0.value.value }.mapValues(\.value)
        if !changed.isEmpty {
            applySettings?(changed)
        }
    }

    private func settingsMayHaveChanged() {
        guard let baseline = loadStamps() else { return }
        if SyncedSettings.current() != baseline.mapValues(\.value) {
            scheduleSync()
        }
    }

    // MARK: - Watching

    private func startWatching() {
        stopWatching()
        guard let session, let folderURL else { return }

        databaseObservation = VaultSyncEngine.observeChanges(in: session.dbManager) { [weak self] in
            Task { @MainActor in self?.scheduleSync() }
        }

        // Cloud services replace files atomically, which shows up as a write to the directory.
        let devices = folderURL.appendingPathComponent(VaultSyncEngine.devicesDirectoryName)
        try? FileManager.default.createDirectory(at: devices, withIntermediateDirectories: true)
        let descriptor = open(devices.path, O_EVTONLY)
        if descriptor >= 0 {
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: descriptor, eventMask: [.write, .rename, .delete], queue: .main
            )
            source.setEventHandler { [weak self] in
                MainActor.assumeIsolated { self?.scheduleSync() }
            }
            source.setCancelHandler { close(descriptor) }
            source.resume()
            folderWatcher = source
        }

        pollTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.scheduleSync() }
        }

        let center = NotificationCenter.default
        notificationObservers = [
            center.addObserver(forName: UserDefaults.didChangeNotification, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.settingsMayHaveChanged() }
            },
            center.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.scheduleSync() }
            },
        ]
    }

    private func stopWatching() {
        databaseObservation?.cancel()
        databaseObservation = nil
        folderWatcher?.cancel()
        folderWatcher = nil
        pollTimer?.invalidate()
        pollTimer = nil
        notificationObservers.forEach(NotificationCenter.default.removeObserver)
        notificationObservers = []
    }
}

enum SyncSetupError: LocalizedError {
    case vaultFolder
    case notASyncFolder
    case vaultExists

    var errorDescription: String? {
        switch self {
        case .vaultFolder:
            return "Choose a folder other than the one the vault is stored in."
        case .notASyncFolder:
            return "That folder doesn't hold a synced SSHoebox vault. On the Mac that has your vault, turn on Sync in Preferences first, then choose the same folder here."
        case .vaultExists:
            return "This Mac already has a vault in its vault folder."
        }
    }
}
