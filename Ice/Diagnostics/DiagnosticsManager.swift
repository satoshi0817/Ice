import AppKit
import Darwin
import MetricKit
import UniformTypeIdentifiers

final class DiagnosticsManager: NSObject, MXMetricManagerSubscriber {
    static let shared = DiagnosticsManager()
    let directory: URL
    let log: RingBufferLog
    let detector: AbnormalExitDetector
    private let logger = Logger(category: "Diagnostics")
    private let payloadLock = NSLock()
    private var terminationSource: DispatchSourceSignal?
    @MainActor private weak var permissions: PermissionsManager?
    @MainActor private var isPrompting = false

    override init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        var directory = home.appendingPathComponent("Library/Application Support/\(Constants.bundleIdentifier)/Diagnostics", isDirectory: true)
        var reports = home.appendingPathComponent("Library/Logs/DiagnosticReports", isDirectory: true)
        #if DEBUG
        let env = ProcessInfo.processInfo.environment
        if let path = env["ICE_DIAGNOSTICS_DIR"] { directory = URL(fileURLWithPath: path, isDirectory: true) }
        if let path = env["ICE_DIAGNOSTIC_REPORTS_DIR"] { reports = URL(fileURLWithPath: path, isDirectory: true) }
        #endif
        self.directory = directory
        self.log = RingBufferLog(url: directory.appendingPathComponent("operations.log"))
        self.detector = AbnormalExitDetector(reportsDirectory: reports, defaults: .standard)
        super.init()
    }

    func record(_ message: String) {
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else { return }
        logger.info(message)
        do { try log.append(message) } catch { logger.error("Diagnostics log write failed: \(error)") }
    }

    @MainActor
    func start(permissions: PermissionsManager) {
        // Hosted tests must not prompt or dirty real session state.
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else { return }
        self.permissions = permissions
        if detector.defaults.string(forKey: "Diagnostics.runningSession") != nil {
            record("Previous session ended without a clean-exit marker (informational only)")
        }
        let identity = detector.beginSession()
        record("App launch: \(Self.appInfo); macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        record("Permissions: \(permissionInfo(permissions))")
        signal(SIGTERM, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            self.detector.markCleanExit(reason: "SIGTERM", record: self.record)
            NSApp.terminate(nil)
        }
        terminationSource = source
        source.resume()
        MXMetricManager.shared.add(self)
        if let identity {
            DispatchQueue.main.async { self.prompt(identity, permissions: permissions) }
        }
        #if DEBUG
        if ProcessInfo.processInfo.environment["ICE_DEBUG_FORCE_CRASH"] == "1" {
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                self.record("DEBUG forced crash")
                fatalError("ICE_DEBUG_FORCE_CRASH")
            }
        }
        #endif
    }

    func stop() {
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else { return }
        record("App clean exit")
        detector.endSession()
        MXMetricManager.shared.remove(self)
    }

    func didReceive(_ payloads: [MXDiagnosticPayload]) {
        payloadLock.lock()
        defer { payloadLock.unlock() }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            for payload in payloads where !(payload.crashDiagnostics ?? []).isEmpty {
                let filename = "MetricKit-\(UUID().uuidString).json"
                try payload.jsonRepresentation().write(to: directory.appendingPathComponent(filename), options: .atomic)
                let start = payload.timeStampBegin
                let end = payload.timeStampEnd
                DispatchQueue.main.async {
                    self.detector.addPendingCrash(identity: filename, start: start, end: end)
                    self.detector.collectNewReport()
                    if let identity = self.detector.pendingIdentity, let permissions = self.permissions {
                        self.prompt(identity, permissions: permissions)
                    }
                }
            }
        } catch { record("MetricKit payload write failed: \(error)") }
    }

    @MainActor
    private func prompt(_ identity: String, permissions: PermissionsManager) {
        let policy = CrashPromptPolicy(defaults: detector.defaults)
        guard !isPrompting, policy.shouldShow(identity) else { return }
        isPrompting = true
        defer { isPrompting = false }
        detector.collectNewReport()
        let alert = NSAlert()
        alert.messageText = String(localized: "Ice quit unexpectedly")
        alert.informativeText = String(localized: "You can save diagnostic information to help find the cause. Nothing is sent automatically.")
        alert.addButton(withTitle: String(localized: "Save Diagnostics…")).keyEquivalent = "\r"
        alert.addButton(withTitle: String(localized: "Close")).keyEquivalent = "\u{1b}"
        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = String(localized: "Don't show again")
        detector.markPendingShown()
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        policy.suppressed = alert.suppressionButton?.state == .on
        if response == .alertFirstButtonReturn { save(permissions: permissions) }
    }

    @MainActor
    func save(permissions: PermissionsManager) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.zip]
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        panel.nameFieldStringValue = "Ice-Diagnostics-\(formatter.string(from: Date())).zip"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let info = "\(Self.appInfo)\nmacOS: \(ProcessInfo.processInfo.operatingSystemVersionString)\nMachine model: \(Self.machineModel)\n\(permissionInfo(permissions))\n"
        let report = detector.latestReport()?.url
        record("Diagnostics export requested")
        let archiver = DiagnosticsArchiver(directory: directory, log: log, temporaryDirectory: FileManager.default.temporaryDirectory)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                self.payloadLock.lock()
                defer { self.payloadLock.unlock() }
                try archiver.archive(to: url, report: report, systemInfo: info)
                DispatchQueue.main.async { NSWorkspace.shared.activateFileViewerSelecting([url]) }
            } catch {
                self.record("Diagnostics export failed: \(error)")
                DispatchQueue.main.async { NSAlert(error: error).runModal() }
            }
        }
    }

    @MainActor
    private func permissionInfo(_ permissions: PermissionsManager) -> String {
        "Accessibility: \(permissions.accessibilityPermission.hasPermission)\nScreen Recording: \(permissions.screenRecordingPermission.hasPermission)"
    }

    private static var appInfo: String {
        let bundle = Bundle.main
        return "App version: \(bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown")\nApp build: \(bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown")"
    }

    private static var machineModel: String {
        var size = 0
        guard sysctlbyname("hw.model", nil, &size, nil, 0) == 0, size > 0 else { return "unknown" }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("hw.model", &buffer, &size, nil, 0) == 0 else { return "unknown" }
        return String(cString: buffer)
    }
}
