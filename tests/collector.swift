#sourceLocation(file: "tests/collector.swift", line: 2)
private func testCollectorRelay() throws {
    let dropPrivileges = "/usr/bin/sudo -n -u '#\(getuid())' -- "
    let stream = try startAuthorizedCollector("printf 'sample\\n'") { command in
        check(command.contains("| " + dropPrivileges + "/usr/bin/nc -U "), "connect as the login user")
        let shell = Process()
        shell.executableURL = URL(fileURLWithPath: "/bin/sh")
        // The test already runs as the login user. Exercise the same pipe and socket.
        shell.arguments = ["-c", command.replacingOccurrences(of: dropPrivileges, with: "")]
        try shell.run()
        shell.waitUntilExit()
        check(shell.terminationStatus == 0, "launch the sample relay")
    }
    defer { try? stream.close() }
    var timeout = timeval(tv_sec: 3, tv_usec: 0)
    let fd = stream.fileDescriptor
    check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0,
          "bound the relay read")
    let data = try stream.readToEnd()
    check(data == Data("sample\n".utf8), "deliver the complete sample and close the stream")
    do {
        _ = try startAuthorizedCollector("exit 1") { _ in throw CancellationError() }
        check(false, "stop when authorization is canceled")
    } catch is CancellationError {}
}

try testCollectorRelay()
print("Passed menu bar collector relay and authorization cancellation checks.")
