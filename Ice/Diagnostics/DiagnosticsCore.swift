import Foundation

final class RingBufferLog {
    let url: URL
    let capacity: Int
    private let lock = NSLock()
    private let clock: () -> Date

    init(url: URL, capacity: Int = 512 * 1024, clock: @escaping () -> Date = Date.init) {
        self.url = url
        self.capacity = max(0, capacity)
        self.clock = clock
    }

    func append(_ message: String) throws {
        lock.lock()
        defer { lock.unlock() }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        var data = (try? Data(contentsOf: url)) ?? Data()
        let line = Data("\(clock().ISO8601Format()) \(message.replacingOccurrences(of: "\n", with: " "))\n".utf8)
        // Keep complete UTF-8 lines; omit a single entry larger than the cap.
        if line.count <= capacity { data.append(line) }
        while data.count > capacity {
            guard let newline = data.firstIndex(of: 10) else { data.removeAll(); break }
            data.removeSubrange(data.startIndex...newline)
        }
        try data.write(to: url, options: .atomic)
    }

    func snapshot() throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try Data(contentsOf: url)
    }
}

struct CrashReport {
    let url: URL
    let date: Date
    var identity: String { "ips:\(url.lastPathComponent):\(date.timeIntervalSince1970)" }
}

final class AbnormalExitDetector {
    let reportsDirectory: URL
    let defaults: UserDefaults
    private let clock: () -> Date

    init(reportsDirectory: URL, defaults: UserDefaults, clock: @escaping () -> Date = Date.init) {
        self.reportsDirectory = reportsDirectory
        self.defaults = defaults
        self.clock = clock
    }

    func latestReport() -> CrashReport? {
        let urls = (try? FileManager.default.contentsOfDirectory(at: reportsDirectory, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
        return urls.compactMap { url -> CrashReport? in
            guard url.lastPathComponent.hasPrefix("Ice"), url.pathExtension == "ips",
                  let values = try? url.resourceValues(forKeys: [.contentModificationDateKey]),
                  let date = values.contentModificationDate else { return nil }
            return CrashReport(url: url, date: date)
        }.sorted { lhs, rhs in
            lhs.date == rhs.date ? lhs.identity > rhs.identity : lhs.date > rhs.date
        }.first
    }

    /// Flags are informational only. First launch baselines historical IPS files.
    func beginSession() -> String? {
        let now = clock()
        let previousLaunch = defaults.object(forKey: "Diagnostics.lastLaunch") as? Date
        defaults.set(previousLaunch ?? now, forKey: "Diagnostics.reportBaseline")
        defaults.removeObject(forKey: "Diagnostics.recoveryWindows")
        if previousLaunch != nil {
            collectNewReport()
        } else if let latest = latestReport() {
            defaults.set(latest.identity, forKey: "Diagnostics.lastReportIdentity")
            defaults.set(latest.date, forKey: "Diagnostics.lastReportDate")
        }
        defaults.set(now, forKey: "Diagnostics.lastLaunch")
        defaults.set(UUID().uuidString, forKey: "Diagnostics.runningSession")
        return pendingIdentity
    }

    func collectNewReport() {
        guard let baseline = defaults.object(forKey: "Diagnostics.reportBaseline") as? Date,
              let latest = latestReport() else { return }
        let seen = defaults.object(forKey: "Diagnostics.lastReportDate") as? Date
        if latest.date > baseline, latest.date > (seen ?? .distantPast) {
            addPendingCrash(identity: latest.identity, start: baseline, end: latest.date)
        }
        defaults.set(latest.identity, forKey: "Diagnostics.lastReportIdentity")
        defaults.set(latest.date, forKey: "Diagnostics.lastReportDate")
    }

    private var pending: [[String: Any]] {
        defaults.array(forKey: "Diagnostics.pendingCrashes") as? [[String: Any]] ?? []
    }

    var pendingIdentity: String? {
        pending.compactMap { $0["identity"] as? String }
            .first { CrashPromptPolicy(defaults: defaults).shouldShow($0) }
    }

    /// Called on the main queue after a MetricKit file is successfully saved.
    func addPendingCrash(identity: String, start: Date, end: Date) {
        let policy = CrashPromptPolicy(defaults: defaults)
        let windows = defaults.array(forKey: "Diagnostics.handledCrashWindows") as? [[String: Any]] ?? []
        let alreadyHandled = windows.contains { window in
            guard let lower = window["start"] as? Date, let upper = window["end"] as? Date else { return false }
            return start <= upper && end >= lower
        }
        if alreadyHandled { policy.markShown(identity); return }
        guard policy.shouldShow(identity) else { return }
        var records = pending
        if !records.contains(where: { $0["identity"] as? String == identity }) {
            records.append(["identity": identity, "start": start, "end": end])
        }
        defaults.set(Array(records.suffix(50)), forKey: "Diagnostics.pendingCrashes")
    }

    /// Coalesces IPS and MetricKit evidence available for the same prompt.
    func markPendingShown() {
        let policy = CrashPromptPolicy(defaults: defaults)
        var windows = defaults.array(forKey: "Diagnostics.handledCrashWindows") as? [[String: Any]] ?? []
        for record in pending {
            if let identity = record["identity"] as? String { policy.markShown(identity) }
            if let start = record["start"] as? Date, let end = record["end"] as? Date {
                windows.append(["start": start, "end": end])
            }
        }
        defaults.set(Array(windows.suffix(20)), forKey: "Diagnostics.handledCrashWindows")
        defaults.removeObject(forKey: "Diagnostics.pendingCrashes")
    }

    func markCleanExit(reason: String, record: (String) -> Void) {
        record("clean exit (\(reason))")
        endSession()
    }

    func endSession() { defaults.removeObject(forKey: "Diagnostics.runningSession") }
}

struct CrashPromptPolicy {
    let defaults: UserDefaults
    var suppressed: Bool {
        get { defaults.bool(forKey: "Diagnostics.suppressPrompt") }
        nonmutating set { defaults.set(newValue, forKey: "Diagnostics.suppressPrompt") }
    }
    func shouldShow(_ identity: String) -> Bool {
        !suppressed && !(defaults.stringArray(forKey: "Diagnostics.handledCrashes") ?? []).contains(identity)
    }
    func markShown(_ identity: String) {
        var handled = defaults.stringArray(forKey: "Diagnostics.handledCrashes") ?? []
        if !handled.contains(identity) { handled.append(identity) }
        defaults.set(Array(handled.suffix(50)), forKey: "Diagnostics.handledCrashes")
    }
}

struct DiagnosticsArchiver {
    let directory: URL
    let log: RingBufferLog
    let temporaryDirectory: URL

    func archive(to destination: URL, report: URL?, systemInfo: String) throws {
        let staging = temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let contents = staging.appendingPathComponent("Ice-Diagnostics", isDirectory: true)
        let fm = FileManager.default
        try fm.createDirectory(at: contents, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: staging) }
        try log.snapshot().write(to: contents.appendingPathComponent("operations.log"))
        try systemInfo.write(to: contents.appendingPathComponent("system-info.txt"), atomically: true, encoding: .utf8)
        if let report { try fm.copyItem(at: report, to: contents.appendingPathComponent(report.lastPathComponent)) }
        for url in try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        where url.lastPathComponent.hasPrefix("MetricKit-") && url.pathExtension == "json" {
            try fm.copyItem(at: url, to: contents.appendingPathComponent(url.lastPathComponent))
        }
        let archive = staging.appendingPathComponent("archive.zip")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = ["-c", "-k", "--norsrc", "--noextattr", "--keepParent", contents.path, archive.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "Ice.Diagnostics.Archive", code: Int(process.terminationStatus))
        }
        try Data(contentsOf: archive).write(to: destination, options: .atomic)
    }
}
