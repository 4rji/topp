#sourceLocation(file: "tests/log.swift", line: 2)
private func logRecords(_ file: URL) throws -> [[String: Any]] {
    let data = try Data(contentsOf: file)
    check(data.last == 10, "every record ends with a newline")
    return try data.split(separator: 10).map { line in
        let record = try JSONSerialization.jsonObject(with: Data(line)) as? [String: Any]
        check(record?["event"] is String, "every line contains a JSON event")
        return record ?? [:]
    }
}

private func permissions(_ file: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
    return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
}

private func testPersistentLogs() throws {
    let files = FileManager.default
    let directory = files.temporaryDirectory.appendingPathComponent("topp-log-tests-\(UUID())")
    defer { try? files.removeItem(at: directory) }
    let active = directory.appendingPathComponent("network.jsonl")
    let detail = "Two lines\nand a quote \" in evidence"
    var connectionHistory = ConnectionHistory()
    let peers = connectionHistory.observe(firstSample.rows, at: instant)
    let finding = Finding(time: instant, process: "Fixture, App", pid: processID,
                          title: "Test finding", detail: detail)
    do {
        let log = SessionLog(directory: directory)
        try log.record(peers, findings: [], at: instant)
        try log.record(peers, findings: [finding], at: seconds(1))
        let closingPeers = peers.mapValues { _ in "FinWait1" }
        try log.record(closingPeers, findings: [], at: seconds(2))
        try log.record([:], findings: [], at: seconds(3))
        let events = try logRecords(active)
        check(events.compactMap { $0["event"] as? String } ==
              ["session_start", "connection_seen", "finding", "connection_state", "connection_ended"],
              "persist live changes once and preserve them before the session closes")
        check(events[1]["remote"] as? String == "203.0.113.8:443" && events[1]["pid"] as? Int == processID,
              "retain the remote endpoint and its owning process")
        check(events[2]["detail"] as? String == detail, "preserve multi-line finding evidence on one JSON line")
        check(events[3]["state"] as? String == "FinWait1" &&
              events[4]["last_seen"] as? String == events[3]["timestamp"] as? String,
              "a disappearance includes the last observed state and timestamp")
        try log.finish(at: seconds(3))
    }
    let saved = try Data(contentsOf: active)
    // Simulate an interrupted write between launches.
    let interrupted = try FileHandle(forWritingTo: active)
    _ = try interrupted.seekToEnd()
    try interrupted.write(contentsOf: Data("{\"event\":".utf8))
    try interrupted.close()
    do {
        let log = SessionLog(directory: directory)
        try log.record(peers, findings: [], at: seconds(4))
        try log.finish(at: seconds(5))
    }
    let appended = try Data(contentsOf: active)
    check(appended.starts(with: saved), "a new instance appends to the previous session")
    let records = try logRecords(active)
    let events = records.compactMap { $0["event"] as? String }
    let sessions = records.compactMap { $0["session"] as? String }
    check(sessions.count == records.count && Set(sessions).count == 2, "attach each event to its session")
    for event in ["session_start", "session_end", "connection_seen"] {
        check(events.filter { $0 == event }.count == 2, "both launches record \(event)")
    }
    let dirMode = try permissions(directory), activeMode = try permissions(active)
    check(dirMode == 0o700 && activeMode == 0o600, "restrict the log directory and active file to the user")

    let busySample = snapshot((1...305).map { socket("198.51.100.2:\($0)", rx: 1, tx: 1) })
    let busyPeers = connectionHistory.observe(busySample.rows, at: seconds(6))
    check(busyPeers.count == 305 && connectionHistory.entries.count == 300,
          "the live table's history limit must not discard observed peers from the log")

    let rotatingDirectory = directory.appendingPathComponent("rotating")
    let smallLog = SessionLog(directory: rotatingDirectory, maxBytes: 1024, archives: 2)
    for index in 1...100 {
        let sample = Finding(time: seconds(index), process: finding.process, pid: finding.pid,
                             title: finding.title, detail: "Finding \(index)")
        try smallLog.record([:], findings: [sample], at: seconds(index))
    }
    try smallLog.finish(at: seconds(101))
    let segments = try files.contentsOfDirectory(at: rotatingDirectory, includingPropertiesForKeys: nil)
        .filter { $0.pathExtension == "jsonl" }
    check(Set(segments.map(\.lastPathComponent)) == ["network.jsonl", "network.1.jsonl", "network.2.jsonl"],
          "keep exactly the active file and the configured number of archives")
    for segment in segments {
        let records = try logRecords(segment)
        let mode = try permissions(segment)
        check(!records.isEmpty && mode == 0o600, "rotated files contain complete private events")
    }
    let finalRecords = try logRecords(rotatingDirectory.appendingPathComponent("network.jsonl"))
    check(finalRecords.last?["event"] as? String == "session_end", "newest events stay in the active log")

    let sharedDirectory = directory.appendingPathComponent("two-writers")
    DispatchQueue.concurrentPerform(iterations: 2) { writer in
        do {
            let log = SessionLog(directory: sharedDirectory, maxBytes: 2048, archives: 20)
            for index in 0..<20 {
                let evidence = Finding(time: seconds(index), process: "Writer", pid: writer + 1,
                                       title: "Test", detail: "\(writer)-\(index)")
                try log.record([:], findings: [evidence], at: seconds(index))
            }
            try log.finish(at: seconds(20))
        } catch {
            check(false, "concurrent writer failed: \(error)")
        }
    }
    let sharedFiles = try files.contentsOfDirectory(at: sharedDirectory, includingPropertiesForKeys: nil)
        .filter { $0.pathExtension == "jsonl" }
    let sharedRecords = try sharedFiles.flatMap(logRecords)
    let details = sharedRecords.compactMap { $0["detail"] as? String }
    check(details.count == 40 && Set(details).count == 40,
          "concurrent writers preserve every finding exactly once across rotations")

    let blockedDirectory = directory.appendingPathComponent("temporarily-blocked")
    try Data().write(to: blockedDirectory)
    let recovering = SessionLog(directory: blockedDirectory)
    do {
        try recovering.record(peers, findings: [finding], at: instant)
        check(false, "report a write failure to the monitor")
    } catch {}
    try files.removeItem(at: blockedDirectory)
    try recovering.record(peers, findings: [], at: seconds(1))
    try recovering.finish(at: seconds(2))
    let recovered = try logRecords(blockedDirectory.appendingPathComponent("network.jsonl"))
    check(recovered.contains { $0["event"] as? String == "log_gap" },
          "mark lost coverage when the log directory becomes writable again")
    let delayedFindings = recovered.filter { $0["event"] as? String == "finding" }
    check(delayedFindings.count == 1 && delayedFindings[0]["detail"] as? String == detail,
          "a temporary write failure preserves a pending finding exactly once")

    let partialDirectory = directory.appendingPathComponent("partially-written-batch")
    try files.createDirectory(at: partialDirectory, withIntermediateDirectories: false)
    let blockedSlots = (1...6).map { partialDirectory.appendingPathComponent("network.\($0).jsonl") }
    for slot in blockedSlots {
        try files.createDirectory(at: slot, withIntermediateDirectories: false)
        try Data().write(to: slot.appendingPathComponent("occupied"))
    }
    let partialLog = SessionLog(directory: partialDirectory, maxBytes: 1, archives: 6)
    do {
        try partialLog.record(peers, findings: [finding], at: instant)
        check(false, "rotation should fail after committing the first record")
    } catch {}
    let prefix = try logRecords(partialDirectory.appendingPathComponent("network.jsonl"))
    check(prefix.count == 1 && prefix[0]["event"] as? String == "session_start", "one event was committed")
    for slot in blockedSlots { try files.removeItem(at: slot) }
    try partialLog.record(peers, findings: [], at: seconds(1))
    try partialLog.finish(at: seconds(2))
    let restoredFiles = try files.contentsOfDirectory(at: partialDirectory, includingPropertiesForKeys: nil)
        .filter { $0.pathExtension == "jsonl" }
    let restored = try restoredFiles.flatMap(logRecords).compactMap { $0["event"] as? String }
    for event in ["session_start", "connection_seen", "finding", "log_gap", "session_end"] {
        check(restored.filter { $0 == event }.count == 1, "recover a partially written batch once for \(event)")
    }
}

do {
    try testPersistentLogs()
    print("Passed persistent session logging, JSON, permissions, and rotation checks.")
} catch {
    check(false, "persistent log test failed: \(error)")
}
