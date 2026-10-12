import XCTest
@testable import Ice

final class DiagnosticsTests: XCTestCase {
    private var directory: URL!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        suite = "IceTests.\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suite)
        try FileManager.default.removeItem(at: directory)
    }

    private func report(_ name: String, date: Date) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try Data("report".utf8).write(to: url)
        try FileManager.default.setAttributes([.modificationDate: date], ofItemAtPath: url.path)
        return url
    }

    func testRingBufferCapAndNewestLines() throws {
        let log = RingBufferLog(url: directory.appendingPathComponent("operations.log"), capacity: 128, clock: { Date(timeIntervalSince1970: 0) })
        for index in 0..<100 {
            try log.append("line-\(index) 日本語")
            XCTAssertLessThanOrEqual(try log.snapshot().count, 128)
        }
        let text = try XCTUnwrap(String(data: log.snapshot(), encoding: .utf8))
        XCTAssertTrue(text.contains("line-99"))
        XCTAssertFalse(text.contains("line-0 "))
        try log.append(String(repeating: "x", count: 1000))
        XCTAssertLessThanOrEqual(try log.snapshot().count, 128)
        XCTAssertTrue(try XCTUnwrap(String(data: log.snapshot(), encoding: .utf8)).contains("line-99"))
    }

    func testConcurrentLogWrites() throws {
        let log = RingBufferLog(url: directory.appendingPathComponent("operations.log"), capacity: 512)
        DispatchQueue.concurrentPerform(iterations: 100) { index in
            do { try log.append("entry-\(index)") } catch { XCTFail("\(error)") }
        }
        XCTAssertLessThanOrEqual(try log.snapshot().count, 512)
        XCTAssertNotNil(String(data: try log.snapshot(), encoding: .utf8))
    }

    func testReportsIgnoreHistoricalAndNonIceFiles() throws {
        let now = Date(timeIntervalSince1970: 1000)
        _ = try report("Ice-old.ips", date: now.addingTimeInterval(-100))
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults, clock: { now })
        XCTAssertNil(detector.beginSession())
        detector.endSession()
        _ = try report("Other.ips", date: now.addingTimeInterval(200))
        _ = try report("Ice.txt", date: now.addingTimeInterval(200))
        _ = try report("Ice-delayed-old.ips", date: now.addingTimeInterval(-50))
        XCTAssertNil(detector.beginSession())
        detector.endSession()
        let newReport = try report("Ice-new.ips", date: now.addingTimeInterval(100))
        XCTAssertEqual(detector.beginSession(), CrashReport(url: newReport, date: now.addingTimeInterval(100)).identity)
        detector.markPendingShown()
        detector.endSession()
        XCTAssertNil(detector.beginSession())
    }

    func testPromptOncePerCrashAndSuppression() {
        let policy = CrashPromptPolicy(defaults: defaults)
        XCTAssertTrue(policy.shouldShow("first"))
        policy.markShown("first")
        XCTAssertFalse(policy.shouldShow("first"))
        XCTAssertTrue(policy.shouldShow("second"))
        policy.markShown("second")
        XCTAssertFalse(policy.shouldShow("first"))
        policy.suppressed = true
        XCTAssertFalse(CrashPromptPolicy(defaults: defaults).shouldShow("third"))
    }

    func testArchiveContentsAndSystemInfo() throws {
        let log = RingBufferLog(url: directory.appendingPathComponent("operations.log"))
        try log.append("last action")
        let ips = try report("Ice-test.ips", date: Date())
        try Data("{}".utf8).write(to: directory.appendingPathComponent("MetricKit-test.json"))
        let zip = directory.appendingPathComponent("export.zip")
        let info = "App version: test\nApp build: 1\nmacOS: test\nMachine model: test\nAccessibility: true\nScreen Recording: false\n"
        try DiagnosticsArchiver(directory: directory, log: log, temporaryDirectory: directory)
            .archive(to: zip, report: ips, systemInfo: info)
        let listing = try unzip(["-Z1", zip.path])
        let entries = listing.split(separator: "\n")
        XCTAssertFalse(entries.contains { $0.hasPrefix("__MACOSX") })
        XCTAssertFalse(entries.contains { $0.contains("/._") })
        for name in ["Ice-test.ips", "operations.log", "MetricKit-test.json", "system-info.txt"] {
            XCTAssertTrue(listing.contains("Ice-Diagnostics/\(name)"))
        }
        let extracted = try unzip(["-p", zip.path, "Ice-Diagnostics/system-info.txt"])
        XCTAssertEqual(extracted, info)
    }

    func testPersistedSuppressionPreventsPromptForNewCrashes() throws {
        let policy = CrashPromptPolicy(defaults: defaults)
        XCTAssertTrue(policy.shouldShow("ips:first"))
        policy.markShown("ips:first")
        policy.suppressed = true // Same value stored from the suppression checkbox.
        let reopened = try XCTUnwrap(UserDefaults(suiteName: suite))
        let restored = CrashPromptPolicy(defaults: reopened)
        XCTAssertTrue(restored.suppressed)
        XCTAssertFalse(restored.shouldShow("MetricKit-new.json"))
        XCTAssertFalse(restored.shouldShow("ips:Ice-new.ips:2000"))
    }

    func testRingBufferOmitsSingleOversizedEntry() throws {
        let log = RingBufferLog(url: directory.appendingPathComponent("operations.log"), capacity: 128)
        try log.append(String(repeating: "日本語", count: 1000))
        XCTAssertEqual(try log.snapshot(), Data())
        try log.append("keep this line")
        let before = try log.snapshot()
        try log.append(String(repeating: "x", count: 1000))
        XCTAssertEqual(try log.snapshot(), before)
    }

    func testArchiveWithoutIPSOrMetricKitFiles() throws {
        let log = RingBufferLog(url: directory.appendingPathComponent("operations.log"))
        try log.append("last action")
        let zip = directory.appendingPathComponent("minimal.zip")
        let info = "App version: test\nApp build: 1\n"
        try DiagnosticsArchiver(directory: directory, log: log, temporaryDirectory: directory)
            .archive(to: zip, report: nil, systemInfo: info)
        let listing = try unzip(["-Z1", zip.path])
        XCTAssertTrue(listing.contains("Ice-Diagnostics/operations.log"))
        XCTAssertTrue(listing.contains("Ice-Diagnostics/system-info.txt"))
        XCTAssertFalse(listing.contains(".ips"))
        XCTAssertFalse(listing.contains("MetricKit-"))
        XCTAssertFalse(listing.split(separator: "\n").contains { $0.hasPrefix("__MACOSX") || $0.contains("/._") })
        XCTAssertEqual(try unzip(["-p", zip.path, "Ice-Diagnostics/operations.log"]),
                       String(data: try log.snapshot(), encoding: .utf8))
        XCTAssertEqual(try unzip(["-p", zip.path, "Ice-Diagnostics/system-info.txt"]), info)
    }

    func testLeftoverFlagWithoutNewIPSDoesNotPrompt() {
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults)
        XCTAssertNil(detector.beginSession())
        XCTAssertNotNil(defaults.string(forKey: "Diagnostics.runningSession"))
        XCTAssertNil(detector.beginSession())
        XCTAssertNil(detector.pendingIdentity)
    }

    func testHistoricalIPSOnFirstLaunchDoesNotPrompt() throws {
        _ = try report("Ice-historical.ips", date: Date(timeIntervalSince1970: 900))
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults,
                                            clock: { Date(timeIntervalSince1970: 1000) })
        XCTAssertNil(detector.beginSession())
        XCTAssertNil(detector.pendingIdentity)
    }

    func testSIGTERMPathMarksCleanExit() {
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults)
        XCTAssertNil(detector.beginSession())
        var messages = [String]()
        detector.markCleanExit(reason: "SIGTERM") { messages.append($0) }
        XCTAssertEqual(messages, ["clean exit (SIGTERM)"])
        XCTAssertNil(defaults.string(forKey: "Diagnostics.runningSession"))
        XCTAssertNil(detector.beginSession())
    }

    func testNewIPSPromptsOnceAndLaterCrashStillPrompts() throws {
        var now = Date(timeIntervalSince1970: 1000)
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults, clock: { now })
        XCTAssertNil(detector.beginSession())
        let ips = try report("Ice-new.ips", date: now.addingTimeInterval(50))
        now = now.addingTimeInterval(100)
        XCTAssertEqual(detector.beginSession(), CrashReport(url: ips, date: Date(timeIntervalSince1970: 1050)).identity)
        detector.markPendingShown()
        XCTAssertNil(detector.pendingIdentity)
        now = now.addingTimeInterval(100)
        XCTAssertNil(detector.beginSession())
        _ = try report("Ice-later.ips", date: now.addingTimeInterval(50))
        now = now.addingTimeInterval(100)
        XCTAssertNotNil(detector.beginSession())
    }

    func testPendingMetricKitPromptsOnNextLaunch() throws {
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults)
        XCTAssertNil(detector.beginSession())
        detector.addPendingCrash(identity: "MetricKit-crash.json", start: Date(timeIntervalSince1970: 1000), end: Date(timeIntervalSince1970: 1050))
        let reopened = try XCTUnwrap(UserDefaults(suiteName: suite))
        let restored = AbnormalExitDetector(reportsDirectory: directory, defaults: reopened)
        XCTAssertEqual(restored.beginSession(), "MetricKit-crash.json")
        restored.markPendingShown()
        XCTAssertNil(restored.beginSession())
    }

    func testIPSAndMetricKitSameWindowPromptOnlyOnce() throws {
        var now = Date(timeIntervalSince1970: 1000)
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults, clock: { now })
        XCTAssertNil(detector.beginSession())
        _ = try report("Ice-new.ips", date: now.addingTimeInterval(50))
        now = now.addingTimeInterval(100)
        let ipsIdentity = try XCTUnwrap(detector.beginSession())
        detector.addPendingCrash(identity: "MetricKit-first.json", start: Date(timeIntervalSince1970: 1000), end: Date(timeIntervalSince1970: 1060))
        detector.markPendingShown()
        let policy = CrashPromptPolicy(defaults: defaults)
        XCTAssertFalse(policy.shouldShow(ipsIdentity))
        XCTAssertFalse(policy.shouldShow("MetricKit-first.json"))
        // A late second source for that window must also be marked handled.
        detector.addPendingCrash(identity: "MetricKit-late.json", start: Date(timeIntervalSince1970: 1020), end: Date(timeIntervalSince1970: 1060))
        XCTAssertNil(detector.pendingIdentity)
        XCTAssertFalse(policy.shouldShow("MetricKit-late.json"))
    }

    func testMetricKitThenDelayedIPSDoesNotPromptAgain() throws {
        var now = Date(timeIntervalSince1970: 1000)
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults, clock: { now })
        XCTAssertNil(detector.beginSession())
        detector.addPendingCrash(identity: "MetricKit-first.json", start: now, end: now.addingTimeInterval(60))
        XCTAssertEqual(detector.pendingIdentity, "MetricKit-first.json")
        detector.markPendingShown()
        _ = try report("Ice-delayed.ips", date: now.addingTimeInterval(50))
        now = now.addingTimeInterval(100)
        XCTAssertNil(detector.beginSession())
    }

    func testPendingHandledAndCrashWindowHistoryCaps() throws {
        let detector = AbnormalExitDetector(reportsDirectory: directory, defaults: defaults)
        for index in 0..<60 {
            let date = Date(timeIntervalSince1970: Double(index * 10))
            detector.addPendingCrash(identity: "MetricKit-\(index).json", start: date, end: date.addingTimeInterval(1))
        }
        XCTAssertEqual(defaults.array(forKey: "Diagnostics.pendingCrashes")?.count, 50)
        XCTAssertEqual(detector.pendingIdentity, "MetricKit-10.json")
        detector.markPendingShown()
        let windows = try XCTUnwrap(defaults.array(forKey: "Diagnostics.handledCrashWindows") as? [[String: Any]])
        XCTAssertEqual(windows.count, 20)
        XCTAssertEqual(windows.first?["start"] as? Date, Date(timeIntervalSince1970: 400))
        XCTAssertNil(defaults.array(forKey: "Diagnostics.pendingCrashes"))
        let policy = CrashPromptPolicy(defaults: defaults)
        for index in 0..<60 { policy.markShown("crash-\(index)") }
        XCTAssertEqual(defaults.stringArray(forKey: "Diagnostics.handledCrashes"), (10..<60).map { "crash-\($0)" })
    }

    private func unzip(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        return try XCTUnwrap(String(data: data, encoding: .utf8))
    }
}
