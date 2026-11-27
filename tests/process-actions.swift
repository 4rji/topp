#sourceLocation(file: "tests/process-actions.swift", line: 2)

private func testProcessTermination() throws {
    let child = Process()
    child.executableURL = URL(fileURLWithPath: "/bin/sleep")
    child.arguments = ["8"]
    try child.run()
    defer { if child.isRunning { child.terminate() } }

    let pid = Int(child.processIdentifier)
    let captured = ProcessMetadata.read(pid: pid)
    let selected = ProcessTarget(pid: pid, name: "test sleep", metadata: captured)
    check(selected.canRequestTermination, "the child must be owned by the test user and identifiable")
    for blockedPID in [-1, 0, 1, Int(getpid()), Int.max] {
        let blocked = ProcessTarget(pid: blockedPID, name: "test", metadata: captured)
        check(!blocked.canRequestTermination, "a protected or invalid PID must have no close action")
    }
    var stale = captured
    stale.started = captured.started?.addingTimeInterval(-1)
    var otherOwner = captured
    otherOwner.user = 0
    var changed = captured
    changed.path = "/different/executable"
    for metadata in [stale, otherOwner, changed, ProcessMetadata()] {
        let target = ProcessTarget(pid: pid, name: selected.name, metadata: metadata)
        check(!target.canRequestTermination, "disable closing when identity or ownership does not match")
        do {
            try target.requestTermination()
            check(false, "revalidate at dispatch, even if the UI requested a stale target")
        } catch {}
        check(child.isRunning, "a rejected action must leave the child running")
    }

    try selected.requestTermination()
    child.waitUntilExit()
    check(child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGTERM,
          "the matching child receives the graceful termination signal")
    check(!selected.canRequestTermination, "a completed process cannot be closed again")
}

try testProcessTermination()
print("Passed process identity and graceful termination checks.")
