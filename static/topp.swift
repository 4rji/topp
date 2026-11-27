// Build for the current Mac: swiftc -O static/topp.swift -o topp
import AppKit
import SwiftUI
import Darwin
import Security

private let displayLocale = Locale(identifier: "en")

struct Port: Hashable, Comparable {
    let transport: String
    let number: Int
    var label: String { "\(transport) \(number)" }

    static func < (lhs: Port, rhs: Port) -> Bool {
        (lhs.number, lhs.transport) < (rhs.number, rhs.transport)
    }
}

struct Owner: Hashable {
    let port: Port
    let pid: Int
}

struct Counter {
    let rx: UInt64?
    let tx: UInt64?

    // When several sockets share a label, the aggregate is known only if all
    // of their counters are present for that direction.
    func combined(with other: Self) -> Self {
        func sum(_ a: UInt64?, _ b: UInt64?) -> UInt64? {
            guard let a, let b else { return nil }
            let (value, overflow) = a.addingReportingOverflow(b)
            return overflow ? nil : value
        }
        return Self(rx: sum(rx, other.rx), tx: sum(tx, other.tx))
    }
}

struct Flow: Hashable {
    let owner: Owner
    let endpointPair: String
}

struct SocketEndpoint: Hashable {
    let host: String
    let port: Int?

    var display: String {
        let address = host.contains(":") ? "[\(host)]" : host
        return "\(address):\(port.map(String.init) ?? "*")"
    }

    var isWildcard: Bool { host == "*" || host == "0.0.0.0" || host == "::" }

    var isLoopback: Bool {
        let address = host.prefix { $0 != "%" }
        return address == "::1" || address.hasPrefix("127.") || address.hasPrefix("::ffff:127.")
    }

    // Numeric nettop labels use address:port for IPv4 and address.port for IPv6.
    // Keep the scope of link-local IPv6 peers, e.g. fe80::1%en0.5353.
    static func parse(_ text: Substring) -> Self? {
        if text == "*" { return Self(host: "*", port: nil) }
        guard let separator = text.lastIndex(where: { $0 == "." || $0 == ":" }) else { return nil }
        let service = text[text.index(after: separator)...]
        let port: Int?
        if service == "*" || service == "0" { port = nil }
        else if let value = UInt16(service), value > 0 { port = Int(value) }
        else { return nil }

        var address = text[..<separator]
        if address.first == "[", address.last == "]" { address = address.dropFirst().dropLast() }
        if address == "*" { return Self(host: "*", port: port) }
        let literal = String(address.prefix { $0 != "%" })
        var ipv4 = in_addr(), ipv6 = in6_addr()
        if inet_pton(AF_INET, literal, &ipv4) == 1, address.count == literal.count {
            return Self(host: literal, port: port)
        }
        guard inet_pton(AF_INET6, literal, &ipv6) == 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &ipv6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return Self(host: String(cString: buffer) + address.dropFirst(literal.count), port: port)
    }
}

struct SocketObservation: Hashable {
    let local: SocketEndpoint
    let remote: SocketEndpoint
    let state: String
}

private enum AppleCodeSignature {
    private static let requirement: SecRequirement? = {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess
        else { return nil }
        return requirement
    }()

    private final class Result {
        let appleSigned: Bool
        let expires: TimeInterval

        init(_ appleSigned: Bool, at now: TimeInterval) {
            self.appleSigned = appleSigned
            self.expires = now + 30
        }
    }

    private static let cache: NSCache<NSString, Result> = {
        let cache = NSCache<NSString, Result>()
        cache.countLimit = 1024
        return cache
    }()

    static func verify(pid: Int, metadata: ProcessMetadata) -> Bool {
        guard let pid = pid_t(exactly: pid), pid > 0, let requirement,
              metadata.started != nil || metadata.path != nil || metadata.user != nil else { return false }
        let key: NSString?
        if let started = metadata.started, let path = metadata.path {
            key = "\(pid)|\(started.timeIntervalSince1970)|\(path)" as NSString
        } else { key = nil }
        let now = ProcessInfo.processInfo.systemUptime
        if let key, let saved = cache.object(forKey: key), saved.expires > now { return saved.appleSigned }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
        let signed = status == errSecSuccess && code.map {
            SecCodeCheckValidity($0, .noNetworkAccess, requirement) == errSecSuccess
        } == true
        if let key { cache.setObject(Result(signed, at: now), forKey: key) }
        return signed
    }
}

struct ProcessMetadata {
    var path: String?
    var parent: pid_t?
    var user: uid_t?
    var started: Date?
    var appleSigned = false

    static func read(pid: Int) -> Self {
        var metadata = Self()
        guard let id = pid_t(exactly: pid), id > 0 else { return metadata }
        var path = [CChar](repeating: 0, count: 4096)
        if proc_pidpath(id, &path, UInt32(path.count)) > 0 { metadata.path = String(cString: path) }
        var keys = [CTL_KERN, KERN_PROC, KERN_PROC_PID, id]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        if sysctl(&keys, 4, &info, &size, nil, 0) == 0, size == MemoryLayout<kinfo_proc>.stride {
            metadata.parent = info.kp_eproc.e_ppid
            metadata.user = info.kp_eproc.e_ucred.cr_uid
            let time = info.kp_proc.p_un.__p_starttime
            if time.tv_sec > 0 {
                metadata.started = Date(timeIntervalSince1970: Double(time.tv_sec) + Double(time.tv_usec) / 1_000_000)
            }
        }
        return metadata
    }
}

struct ProcessTarget {
    let pid: Int
    let name: String
    let metadata: ProcessMetadata

    private var ownedPID: pid_t? {
        let user = geteuid()
        guard user != 0, metadata.user == user, metadata.started != nil,
              let id = pid_t(exactly: pid), id > 1, id != getpid() else { return nil }
        return id
    }

    private func matchesCurrentProcess() -> Bool {
        let current = ProcessMetadata.read(pid: pid)
        return current.started == metadata.started && current.user == metadata.user
            && (metadata.path == nil || current.path == metadata.path)
    }

    var canRequestTermination: Bool { ownedPID != nil && matchesCurrentProcess() }

    // Monterey and earlier Sonoma releases lack this libproc symbol.
    private typealias TokenSignal = @convention(c) (UnsafeMutablePointer<audit_token_t>, Int32) -> Int32
    private static let tokenSignal: TokenSignal? = {
        guard let library = dlopen(nil, RTLD_LAZY) else { return nil }
        defer { dlclose(library) }
        guard let symbol = dlsym(library, "proc_signal_with_audittoken") else { return nil }
        return unsafeBitCast(symbol, to: TokenSignal.self)
    }()

    private func token(for id: pid_t) throws -> audit_token_t {
        var task = mach_port_name_t()
        guard task_name_for_pid(mach_task_self_, id, &task) == KERN_SUCCESS else {
            throw LaunchError("The process exited or macOS denied access to its identity.")
        }
        defer { mach_port_deallocate(mach_task_self_, task) }
        var audit = audit_token_t()
        let capacity = MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size
        var count = mach_msg_type_number_t(capacity)
        let result = withUnsafeMutablePointer(to: &audit) {
            $0.withMemoryRebound(to: integer_t.self, capacity: capacity) {
                task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS, count == capacity else {
            throw LaunchError("macOS could not verify the identity of the selected process.")
        }
        return audit
    }

    func requestTermination() throws {
        guard let id = ownedPID else {
            throw LaunchError("Choose a process owned by your account with a known start time.")
        }
        // Acquire the kernel's process generation *before* checking the start
        // time. A PID reused after that check cannot receive the token's signal.
        let audit = try Self.tokenSignal.map { _ in try token(for: id) }
        guard matchesCurrentProcess() else {
            throw LaunchError("The selected process exited or changed since this row was recorded.")
        }
        let error: Int32
        if var token = audit, let send = Self.tokenSignal {
            error = send(&token, SIGTERM)
        } else {
            // The older API accepts only a PID, immediately after revalidation.
            error = kill(id, SIGTERM) == 0 ? 0 : errno
        }
        guard error == 0 else { throw POSIXError(POSIXErrorCode(rawValue: error) ?? .EIO) }
    }
}

struct PortRow: Identifiable {
    enum Field { case process, state, rx, tx }

    let id: Owner
    let process: String
    var metadata = ProcessMetadata()
    var states = Set<String>()
    var sockets = Set<SocketObservation>()
    var hasUnparsedPeer = false
    var rx = 0.0
    var tx = 0.0
    var hasRxRate = false
    var hasTxRate = false
    var hasRate: Bool { hasRxRate || hasTxRate }
    var changed: Set<Field> = []
    var rxText: String { hasRxRate ? rate(rx) : "—" }
    var txText: String { hasTxRate ? rate(tx) : "—" }

    var state: String {
        return states.map { $0 == "Listen" ? "Listening" : $0 }.sorted().joined(separator: " · ")
    }

    mutating func markChanges(since old: PortRow) {
        changed = []
        if process != old.process { changed.insert(.process) }
        if states != old.states { changed.insert(.state) }
        if rxText != old.rxText { changed.insert(.rx) }
        if txText != old.txText { changed.insert(.tx) }
    }
}

struct Snapshot {
    var rows = [Owner: PortRow]()
    var counters = [Flow: Counter]()
    private var process: (pid: Int, name: String, metadata: ProcessMetadata)?
    private var columns = [String: Int]()
    private var includesTime = false
    private(set) var captureTime: Double?
    var hasHeader: Bool { columns["bytes_in"] != nil && columns["bytes_out"] != nil }

    mutating func read(_ line: String) {
        // The three requested fields and a trailing empty field follow the name.
        // Split from the right so commas in a process name do not shift columns.
        var fields = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        if fields.last == "" { fields.removeLast() }
        if fields.first == "time" {
            includesTime = true
            fields.removeFirst()
        } else if includesTime && !fields.isEmpty {
            let time = fields.removeFirst()
            if captureTime == nil {
                let parts = time.split(separator: ":").compactMap { Double($0) }
                if parts.count == 3 { captureTime = parts[0] * 3600 + parts[1] * 60 + parts[2] }
            }
        }
        if fields.first == "" {
            columns.removeAll()
            for (i, name) in fields.enumerated().dropFirst() { columns[name] = i }
            process = nil
            return
        }
        guard hasHeader, fields.count > columns.count else { return }
        let headCount = fields.count - columns.count
        let label = fields.prefix(headCount).joined(separator: ",")
            .trimmingCharacters(in: CharacterSet(charactersIn: " \""))
        func field(_ name: String) -> String {
            guard let i = columns[name] else { return "" }
            return fields[headCount - 1 + i]
        }
        let parts = label.split(separator: " ", maxSplits: 1)
        let protocols = ["tcp4": "TCP", "tcp6": "TCP", "udp4": "UDP", "udp6": "UDP",
                         "quic4": "QUIC", "quic6": "QUIC"]
        guard parts.count == 2, let transport = protocols[String(parts[0])],
              let arrow = parts[1].range(of: "<->") else {
            process = nil
            if let dot = label.lastIndex(of: "."), let pid = Int(label[label.index(after: dot)...]) {
                var metadata = ProcessMetadata.read(pid: pid)
                metadata.appleSigned = AppleCodeSignature.verify(pid: pid, metadata: metadata)
                var name = String(label[..<dot])
                // nettop truncates names to 15 bytes. Expand the executable name
                // when macOS permits the GUI to look up this PID.
                if name.utf8.count >= 15, let path = metadata.path {
                    let executable = URL(fileURLWithPath: path).lastPathComponent
                    if executable.hasPrefix(name) { name = executable }
                }
                process = (pid, name, metadata)
            }
            return
        }
        guard let process, let local = SocketEndpoint.parse(parts[1][..<arrow.lowerBound]),
              let port = local.port else { return }
        let owner = Owner(port: Port(transport: transport, number: port), pid: process.pid)
        let value = field("state")
        let state = value.isEmpty ? "Bound" : value
        rows[owner, default: PortRow(id: owner, process: process.name, metadata: process.metadata)].states.insert(state)
        if let remote = SocketEndpoint.parse(parts[1][arrow.upperBound...]) {
            rows[owner]?.sockets.insert(SocketObservation(local: local, remote: remote, state: state))
        } else {
            rows[owner]?.hasUnparsedPeer = true
        }
        let key = Flow(owner: owner, endpointPair: label)
        let counter = Counter(rx: UInt64(field("bytes_in")), tx: UInt64(field("bytes_out")))
        counters[key] = counters[key]?.combined(with: counter) ?? counter
    }

    func rates(since previous: Snapshot?, seconds: Double) -> [Owner: PortRow] {
        var result = rows
        if let previous, seconds > 0 {
            for (key, current) in counters {
                // The first observation is a lifetime total, with no measured interval.
                guard let old = previous.counters[key],
                      let last = previous.rows[key.owner], let row = rows[key.owner],
                      last.metadata.started == row.metadata.started, last.process == row.process else { continue }
                if let rx = current.rx, let previousRx = old.rx, rx >= previousRx {
                    result[key.owner]?.rx += Double(rx - previousRx) / seconds
                    result[key.owner]?.hasRxRate = true
                }
                if let tx = current.tx, let previousTx = old.tx, tx >= previousTx {
                    result[key.owner]?.tx += Double(tx - previousTx) / seconds
                    result[key.owner]?.hasTxRate = true
                }
            }
            // An idle TCP listener has no byte counters of its own.
            for (key, row) in rows where row.states == ["Listen"] {
                result[key]?.hasRxRate = true
                result[key]?.hasTxRate = true
            }
        }
        return result
    }
}

struct Finding: Identifiable {
    let id = UUID()
    let time: Date
    let process: String
    let pid: Int
    let title: String
    let detail: String
    var metadata = ProcessMetadata()
}

struct NetworkInspection {
    private struct ProcessInstance: Hashable {
        let pid: Int
        let name: String
        let started: Date?
    }

    private struct Listener: Hashable {
        let process: ProcessInstance
        let port: Int
    }

    private struct Peer: Hashable {
        let process: ProcessInstance
        let host: String
    }

    private struct AttemptWindow {
        var ports = [Int: Date]()
        var lastReport = Date.distantPast
    }

    private struct Upload: Hashable {
        let process: ProcessInstance
        let localPort: Int
        let remote: SocketEndpoint
    }

    private struct Streak {
        var lastSample = Date.distantPast
        var consecutive = 0
        var lowestRate = Double.infinity
        var lastReport = Date.distantPast
    }

    private var listeners = [Listener: Date]()
    private var attempts = [Peer: AttemptWindow]()
    private var uploads = [Upload: Streak]()
    private var previousSample: Date?
    private let capacity = 1024  // Maximum tracked keys per rule.
    private let cooldown: TimeInterval = 60

    mutating func inspect(_ rows: [Owner: PortRow], at now: Date) -> [Finding] {
        // A backwards clock jump invalidates elapsed-time comparisons.
        if let previousSample, now < previousSample { self = Self() }
        let lastSample = previousSample
        previousSample = now
        let cutoff = now.addingTimeInterval(-cooldown)
        let attemptCutoff = now.addingTimeInterval(-30)
        listeners = listeners.filter { $0.value > cutoff || $0.value == lastSample }
        attempts = attempts.compactMapValues { window in
            var recent = window
            recent.ports = recent.ports.filter { $0.value >= attemptCutoff }
            return recent.ports.isEmpty && recent.lastReport <= cutoff ? nil : recent
        }
        uploads = uploads.filter { $0.value.lastSample == lastSample || $0.value.lastReport > cutoff }
        var findings = [Finding]()
        for row in rows.values where row.id.port.transport == "TCP" {
            let process = ProcessInstance(pid: row.id.pid, name: row.process, started: row.metadata.started)
            func finding(_ title: String, _ detail: String) -> Finding {
                Finding(time: now, process: row.process, pid: row.id.pid, title: title, detail: detail,
                        metadata: row.metadata)
            }
            for socket in row.sockets {
                if socket.state == "Listen" && socket.local.isWildcard {
                    let key = Listener(process: process, port: row.id.port.number)
                    if listeners[key] == nil && listeners.count >= capacity { continue }
                    let seen = listeners.updateValue(now, forKey: key)
                    if lastSample != nil && seen == nil {
                        findings.append(finding("New wildcard listener", "TCP \(socket.local.display) is listening on a wildcard address."))
                    }
                }
                // Established connections have no initiator information. A SYN
                // sent by this Mac provides evidence of a local connection attempt.
                let state = socket.state.lowercased()
                guard ["synsent", "syn_sent", "syn-sent", "syn sent"].contains(state),
                      !socket.remote.isWildcard, !socket.remote.isLoopback, let port = socket.remote.port else { continue }
                let peer = Peer(process: process, host: socket.remote.host)
                guard attempts[peer] != nil || attempts.count < capacity else { continue }
                var window = attempts[peer] ?? AttemptWindow()
                guard window.lastReport <= cutoff else { continue }
                window.ports[port] = now
                if window.ports.count == 8 {
                    let list = window.ports.keys.sorted().map(String.init).joined(separator: ", ")
                    findings.append(finding("TCP attempts to multiple ports",
                        "Observed SYN sent to \(peer.host) on 8 distinct TCP ports within 30 seconds (\(list))."))
                    window.lastReport = now
                    window.ports.removeAll()
                }
                attempts[peer] = window
            }

            // Counters belong to the whole row. Attribute a rate only when every
            // observed socket on that port has the same concrete remote endpoint.
            guard row.hasTxRate, row.tx >= 5_000_000, !row.hasUnparsedPeer, let remote = row.sockets.first?.remote,
                  remote.port != nil, !remote.isWildcard, !remote.isLoopback,
                  row.sockets.allSatisfy({ $0.state == "Established" && $0.remote == remote }) else { continue }
            let upload = Upload(process: process, localPort: row.id.port.number, remote: remote)
            guard uploads[upload] != nil || uploads.count < capacity else { continue }
            var streak = uploads[upload] ?? Streak()
            if streak.lastSample != lastSample || now.timeIntervalSince(streak.lastSample) > 5 {
                streak.consecutive = 0
                streak.lowestRate = .infinity
            }
            if streak.consecutive < 3 {
                streak.consecutive += 1
                streak.lowestRate = min(streak.lowestRate, row.tx)
                if streak.consecutive == 3 && streak.lastReport <= cutoff {
                    findings.append(finding("Sustained upload",
                        "Outbound traffic from TCP \(row.id.port.number) to \(remote.display) reached 5 MB/s in 3 consecutive samples (lowest sample ≈ \(rate(streak.lowestRate)))."))
                    streak.lastReport = now
                }
            }
            streak.lastSample = now
            uploads[upload] = streak
        }
        return findings
    }
}

func rate(_ value: Double) -> String {
    let units = ["B/s", "KB/s", "MB/s", "GB/s"]
    var amount = value, index = 0
    while amount >= 1000 && index < units.count - 1 { amount /= 1000; index += 1 }
    return String(format: index > 0 && amount < 10 ? "%.1f %@" : "%.0f %@", amount, units[index])
}

private let endOfSample = "--topp-sample--"

// sudo authenticates on the caller's terminal before it backgrounds the sampler.
// Only fixed system commands run as root. A closed output pipe ends the loop,
// including when the unprivileged GUI is killed. One-shot samples flush even on idle Macs.
func startCollector() throws -> FileHandle {
    let script = """
    trap '' HUP
    exec 2>&1
    while /usr/bin/nettop -n -x -L 1 -J time,state,bytes_in,bytes_out; do
        printf '%s\\n' '\(endOfSample)' || exit
        /bin/sleep 1 || exit
    done
    """
    let pipe = Pipe()
    let pid = try spawn(["/usr/bin/sudo", "-b", "--", "/bin/sh", "-c", script],
                        output: pipe.fileHandleForWriting.fileDescriptor)
    try pipe.fileHandleForWriting.close()
    var status: Int32 = 0
    var waited: pid_t
    repeat { waited = waitpid(pid, &status, 0) } while waited == -1 && errno == EINTR
    guard waited == pid, status == 0 else {
        throw LaunchError("sudo could not start the monitor. Run topp from Terminal using an administrator account.")
    }
    return pipe.fileHandleForReading
}

struct RotatingLogFile {
    let directory: URL
    let maxBytes: Int
    let archives: Int

    private func failure() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }

    private func openFile(_ name: String, in folder: Int32) throws -> FileHandle {
        let flags = O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        var fd = openat(folder, name, flags, mode_t(0o600))
        // Darwin can report ENOENT when another writer wins the initial creation.
        if fd < 0 && errno == ENOENT { fd = openat(folder, name, flags, mode_t(0o600)) }
        guard fd >= 0 else { throw failure() }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw failure() }
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1
        else { throw POSIXError(.EPERM) }
        if (info.st_mode & 0o7777) != 0o600, fchmod(fd, 0o600) != 0 { throw failure() }
        return handle
    }

    // A killed writer can leave part of its final record. Resume at the last newline.
    private func recoverEnd(of file: FileHandle) throws -> UInt64 {
        let end = try file.seekToEnd()
        var position = end
        var window: UInt64 = 1
        while position > 0 {
            let count = min(position, window)
            position -= count
            try file.seek(toOffset: position)
            let bytes = try file.read(upToCount: Int(count)) ?? Data()
            guard bytes.count == Int(count) else { throw POSIXError(.EIO) }
            if let last = bytes.lastIndex(of: 10) {
                let boundary = position + UInt64(last + 1)
                if boundary < end { try file.truncate(atOffset: boundary) }
                try file.seek(toOffset: boundary)
                return boundary
            }
            window = 8192
        }
        if end > 0 { try file.truncate(atOffset: 0) }
        return 0
    }

    private func rotate(in folder: Int32) throws {
        if archives == 0 {
            guard unlinkat(folder, "network.jsonl", 0) == 0 else { throw failure() }
            return
        }
        for slot in stride(from: archives, through: 1, by: -1) {
            let previous = slot == 1 ? "network.jsonl" : "network.\(slot - 1).jsonl"
            if renameat(folder, previous, folder, "network.\(slot).jsonl") != 0 {
                if errno == ENOENT && slot > 1 { continue }
                throw failure()
            }
        }
    }

    func append(_ records: [Data], didWrite: () -> Void = {}) throws {
        guard !records.isEmpty else { return }
        guard maxBytes > 0, archives >= 0 else { throw POSIXError(.EINVAL) }
        if mkdir(directory.path, 0o700) != 0 {
            if errno == ENOENT {
                try FileManager.default.createDirectory(at: directory.deletingLastPathComponent(),
                                                        withIntermediateDirectories: true)
                if mkdir(directory.path, 0o700) != 0 && errno != EEXIST { throw failure() }
            } else if errno != EEXIST { throw failure() }
        }
        let folder = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard folder >= 0 else { throw failure() }
        defer { close(folder) }
        var info = stat()
        guard fstat(folder, &info) == 0 else { throw failure() }
        guard info.st_uid == geteuid() else { throw POSIXError(.EPERM) }
        if (info.st_mode & 0o7777) != 0o700, fchmod(folder, 0o700) != 0 { throw failure() }

        // The lock's inode remains stable when the active log is renamed.
        let lock = try openFile(".writer.lock", in: folder)
        defer { try? lock.close() }
        while flock(lock.fileDescriptor, LOCK_EX) != 0 {
            if errno != EINTR { throw failure() }
        }
        var file = try openFile("network.jsonl", in: folder)
        var size = try recoverEnd(of: file)
        for record in records {
            var line = record
            line.append(10)
            if size > 0 && size + UInt64(line.count) > UInt64(maxBytes) {
                try file.close()
                try rotate(in: folder)
                file = try openFile("network.jsonl", in: folder)
                size = 0
            }
            try file.write(contentsOf: line)
            didWrite()
            size += UInt64(line.count)
        }
        try file.close()
    }
}

struct ConnectionHistory {
    struct Key: Hashable {
        let owner: Owner
        let process: String
        let started: Date?
        let local: SocketEndpoint
        let remote: SocketEndpoint
    }

    struct Entry: Identifiable {
        let id: Key
        let firstSeen: Date
        var lastSeen: Date
        var states: String
        let metadata: ProcessMetadata
        var appleSigned: Bool { metadata.appleSigned }
        var remote: SocketEndpoint { id.remote }
        var process: String { id.process }
        var pid: Int { id.owner.pid }
        var transport: String { id.owner.port.transport }
    }

    private(set) var entries = [Entry]()

    @discardableResult
    mutating func observe(_ rows: [Owner: PortRow], at time: Date) -> [Key: String] {
        var recorded = Dictionary(uniqueKeysWithValues: entries.map { ($0.id, $0) })
        var observed = [Key: String]()
        for row in rows.values {
            let peers = row.sockets.filter { !$0.remote.isWildcard && $0.remote.port != nil }
            let groups = Dictionary(grouping: peers) {
                Key(owner: row.id, process: row.process, started: row.metadata.started,
                    local: $0.local, remote: $0.remote)
            }
            for (key, sockets) in groups {
                let states = Set(sockets.map(\.state)).sorted().joined(separator: " · ")
                observed[key] = states
                recorded[key] = Entry(id: key, firstSeen: recorded[key]?.firstSeen ?? time,
                                      lastSeen: time, states: states, metadata: row.metadata)
            }
        }
        entries = Array(recorded.values.sorted {
            if $0.lastSeen != $1.lastSeen { return $0.lastSeen > $1.lastSeen }
            if $0.firstSeen != $1.firstSeen { return $0.firstSeen > $1.firstSeen }
            return ($0.pid, $0.id.owner.port, $0.remote.display, $0.id.local.display)
                < ($1.pid, $1.id.owner.port, $1.remote.display, $1.id.local.display)
        }.prefix(300))
        return observed
    }
}

final class SessionLog {
    static let directory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/topp", isDirectory: true)
    static var fileURL: URL { directory.appendingPathComponent("network.jsonl") }

    private struct Record: Encodable {
        let event: String
        let session: UUID
        let timestamp: Date
        var process: String?
        var pid: Int?
        var process_started: Date?
        var local: String?
        var remote: String?
        var transport: String?
        var state: String?
        var last_seen: Date?
        var title: String?
        var detail: String?
        var gap_since: Date?
        var dropped_events: Int?
    }

    private let file: RotatingLogFile
    private let session = UUID()
    private let encoder = JSONEncoder()
    // The sampler and the AppKit termination callback may overlap.
    private let lock = NSLock()
    private var previous = [ConnectionHistory.Key: String]()
    private var previousTime: Date?
    private var gapSince: Date?
    private var pending = [Data]()
    private var dropped = 0
    private var finished = false

    init(directory: URL = SessionLog.directory, maxBytes: Int = 10 * 1024 * 1024, archives: Int = 5) {
        file = RotatingLogFile(directory: directory, maxBytes: maxBytes, archives: archives)
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    }

    func record(_ peers: [ConnectionHistory.Key: String], findings: [Finding], at time: Date) throws {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return }
        var batch = [Record]()
        if previousTime == nil {
            batch.append(Record(event: "session_start", session: session, timestamp: time))
        }
        func connection(_ event: String, _ key: ConnectionHistory.Key, state: String, lastSeen: Date) -> Record {
            Record(event: event, session: session, timestamp: time, process: key.process,
                   pid: key.owner.pid, process_started: key.started, local: key.local.display,
                   remote: key.remote.display, transport: key.owner.port.transport, state: state,
                   last_seen: lastSeen)
        }
        for (key, state) in peers where previous[key] != state {
            let event = previous[key] == nil ? "connection_seen" : "connection_state"
            batch.append(connection(event, key, state: state, lastSeen: time))
        }
        if let previousTime {
            for (key, state) in previous where peers[key] == nil {
                batch.append(connection("connection_ended", key, state: state, lastSeen: previousTime))
            }
        }
        for finding in findings {
            batch.append(Record(event: "finding", session: session, timestamp: finding.time,
                                process: finding.process, pid: finding.pid, title: finding.title, detail: finding.detail))
        }
        previous = peers
        previousTime = time
        try flush(batch, at: time)
    }

    func finish(at time: Date) throws {
        lock.lock()
        defer { lock.unlock() }
        let closing = !finished && previousTime != nil
        let batch = closing ? [Record(event: "session_end", session: session, timestamp: time)] : []
        finished = true
        try flush(batch, at: time)
    }

    private func flush(_ batch: [Record], at time: Date) throws {
        guard !batch.isEmpty || gapSince != nil else { return }
        var lines = pending + (try batch.map(encoder.encode))
        let eventCount = lines.count
        if let gapSince {
            let recovery = Record(event: "log_gap", session: session, timestamp: time,
                                  gap_since: gapSince, dropped_events: dropped)
            lines.append(try encoder.encode(recovery))
        }
        var written = 0
        do {
            try file.append(lines) { written += 1 }
            pending.removeAll()
            dropped = 0
            gapSince = nil
        } catch {
            if gapSince == nil { gapSince = time }
            // Retry only complete records that did not reach disk. Bound memory if
            // a volume stays unavailable and report the loss on recovery.
            pending.removeAll()
            var bytes = 0
            for line in lines.prefix(eventCount).dropFirst(written) {
                if bytes + line.count <= 2 * 1024 * 1024 {
                    pending.append(line)
                    bytes += line.count
                } else {
                    dropped += 1
                }
            }
            throw error
        }
    }
}

private struct MenuTrafficRates {
    var rx: Double?
    var tx: Double?
    var total: Double { (rx ?? 0) + (tx ?? 0) }
    var rxText: String { rx.map(rate) ?? "—" }
    var txText: String { tx.map(rate) ?? "—" }

    mutating func add(_ row: PortRow) {
        if row.hasRxRate { rx = (rx ?? 0) + row.rx }
        if row.hasTxRate { tx = (tx ?? 0) + row.tx }
    }
}

struct MenuProcessTraffic: Identifiable {
    struct ID: Hashable {
        let pid: Int
        let started: Date?
        let name: String
    }
    let id: ID
    let representative: PortRow
    fileprivate var rates = MenuTrafficRates()
    var name: String { id.name }
    var pid: Int { id.pid }
    var rxText: String { rates.rxText }
    var txText: String { rates.txText }
}

struct MenuBarSnapshot {
    static let rateCharacterLimit = 7
    let downloadText: String
    let uploadText: String
    var text: String { "↓\(downloadText) ↑\(uploadText)" }
    let summary: String
    let accessibilitySummary: String
    let processes: [MenuProcessTraffic]
}

final class Monitor: ObservableObject {
    @Published var rows = [PortRow]()
    @Published var sortOrder = [KeyPathComparator(\PortRow.id.port.number)] {
        didSet {
            if sortOrder != oldValue { rows = sortedForTable(rows) }
        }
    }
    @Published var selection = Set<Owner>()
    @Published var query = ""
    private var queryBeforeReview: String?
    @Published fileprivate var tab = MonitorTab.ports {
        didSet {
            if oldValue == .findings && tab != .findings, let saved = queryBeforeReview {
                if query.isEmpty { query = saved }
                queryBeforeReview = nil
            }
        }
    }
    @Published var status = "Reading ports…"
    @Published var samplerStopped = false
    @Published var menuBarIconOnly: Bool {
        didSet {
            defaults.set(menuBarIconOnly, forKey: "menuBarIconOnly")
            onChange?()
        }
    }
    @Published var windowIsKey = false
    @Published var logError: String?
    @Published fileprivate var actionNotice: String?
    let log: SessionLog
    @Published var connections = [ConnectionHistory.Entry]()
    @Published private var reviewedFindingIDs = Set<UUID>()
    @Published var findings = [Finding]() {
        didSet {
            let retained = reviewedFindingIDs.intersection(findings.map(\.id))
            if retained != reviewedFindingIDs { reviewedFindingIDs = retained }
        }
    }
    @Published var hidden: Set<String>
    @Published var hideAppleSigned: Bool {
        didSet {
            defaults.set(hideAppleSigned, forKey: "hideAppleSigned")
            onChange?()
        }
    }
    @Published var fontSize: Double {
        didSet { defaults.set(fontSize, forKey: "fontSize") }
    }
    static let defaultFontSize = Double(NSFont.systemFontSize)
    static let fontSizes = 10.0...30.0
    var onChange: (() -> Void)?
    // Keep hidden ports saved before the command was renamed to topp.
    private let defaults: UserDefaults
    init(defaults: UserDefaults = UserDefaults(suiteName: "org.4rji.puertosmac")!, log: SessionLog = SessionLog()) {
        self.defaults = defaults
        self.log = log
        menuBarIconOnly = defaults.bool(forKey: "menuBarIconOnly")
        hideAppleSigned = defaults.bool(forKey: "hideAppleSigned")
        hidden = Set(defaults.stringArray(forKey: "hiddenPorts") ?? [])
        let saved = defaults.double(forKey: "fontSize")
        fontSize = Self.fontSizes.contains(saved) ? saved : Self.defaultFontSize
    }

    func zoom(by step: Double) {
        fontSize = min(max(fontSize + step, Self.fontSizes.lowerBound), Self.fontSizes.upperBound)
    }

    // Port numbers never change, so keeping that order live does not move rows
    // under the pointer. Other columns keep their order and append new rows.
    private var sortsByPort: Bool { sortOrder.first?.keyPath == \PortRow.id.port.number }

    var visible: [PortRow] {
        rows.filter { !hidden.contains($0.id.port.label) && !(hideAppleSigned && $0.metadata.appleSigned) }
    }
    var visibleConnections: [ConnectionHistory.Entry] {
        hideAppleSigned ? connections.filter { !$0.appleSigned } : connections
    }
    var visibleFindings: [Finding] {
        hideAppleSigned ? findings.filter { !$0.metadata.appleSigned } : findings
    }

    var unreadFindings: [Finding] {
        visibleFindings.filter { !reviewedFindingIDs.contains($0.id) }
    }

    func addFindings(_ newFindings: [Finding]) {
        guard !newFindings.isEmpty else { return }
        findings = Array((newFindings + findings).prefix(200))
    }

    func markFindingsReviewed(_ ids: Set<UUID>) {
        let newlyReviewed = ids.intersection(unreadFindings.map(\.id))
        guard !newlyReviewed.isEmpty else { return }
        reviewedFindingIDs.formUnion(newlyReviewed)
        onChange?()
    }

    func reviewNewFindings() {
        if tab != .findings { queryBeforeReview = query }
        query = ""
        tab = .findings
    }

    var menuBarSnapshot: MenuBarSnapshot {
        var totals = MenuTrafficRates()
        var byProcess = [MenuProcessTraffic.ID: MenuProcessTraffic]()
        for row in visible where row.hasRate {
            totals.add(row)
            let id = MenuProcessTraffic.ID(pid: row.id.pid, started: row.metadata.started, name: row.process)
            byProcess[id, default: MenuProcessTraffic(id: id, representative: row)].rates.add(row)
        }
        let processes = byProcess.values.filter { $0.rates.total > 0 }.sorted {
            if $0.rates.total != $1.rates.total { return $0.rates.total > $1.rates.total }
            if $0.name != $1.name { return $0.name < $1.name }
            if $0.pid != $1.pid { return $0.pid < $1.pid }
            return ($0.id.started ?? .distantPast) < ($1.id.started ?? .distantPast)
        }
        let summary = "↓ \(totals.rxText)   ↑ \(totals.txText)"
        func kilobytes(_ bytes: Double) -> String {
            let value = bytes / 1000
            let style = FloatingPointFormatStyle<Double>.number.locale(displayLocale).grouping(.never)
            for decimals in (0...3).reversed() {
                let numeric = value.formatted(style.precision(.fractionLength(0...decimals)))
                if numeric.count <= MenuBarSnapshot.rateCharacterLimit { return numeric }
            }
            return value.formatted(style.notation(.scientific).precision(.fractionLength(0...1)))
        }
        let download = samplerStopped ? nil : totals.rx.map(kilobytes)
        let upload = samplerStopped ? nil : totals.tx.map(kilobytes)
        let downDescription = download.map { "\($0) KB/s" } ?? "unavailable"
        let upDescription = upload.map { "\($0) KB/s" } ?? "unavailable"
        let readable = "Download \(downDescription), upload \(upDescription)"
        return MenuBarSnapshot(downloadText: download ?? "—", uploadText: upload ?? "—", summary: summary,
                               accessibilitySummary: readable, processes: processes)
    }

    private func sortedForTable(_ values: [PortRow]) -> [PortRow] {
        values.sorted(using: sortOrder + [KeyPathComparator(\.id.port.number),
                                          KeyPathComparator(\.id.port.transport),
                                          KeyPathComparator(\.id.pid)])
    }

    func applySample(_ sample: [Owner: PortRow]) {
        var additions = sample
        let existing = rows.compactMap { old -> PortRow? in
            guard var row = additions.removeValue(forKey: old.id) else { return nil }
            row.markChanges(since: old)
            return row
        }
        let combined = existing + Array(additions.values)
        rows = sortsByPort ? sortedForTable(combined) : existing + sortedForTable(Array(additions.values))
        if !selection.isSubset(of: sample.keys) { selection.formIntersection(sample.keys) }
    }

    func saveHidden(_ values: Set<String>) {
        hidden = values
        defaults.set(values.sorted(), forKey: "hiddenPorts")
        onChange?()
    }

    func start() {
        DispatchQueue.global(qos: .utility).async {
            var sample = Snapshot(), previous: Snapshot?
            var history = ConnectionHistory(), inspection = NetworkInspection()
            var lastTime = 0.0, diagnostic = ""
            while let line = readLine() {
                guard line == endOfSample else {
                    if line.hasPrefix("nettop:") || line.hasPrefix("sudo:") { diagnostic = line }
                    sample.read(line)
                    continue
                }
                guard sample.hasHeader else { diagnostic = "Unrecognized nettop output format."; break }
                let now = ProcessInfo.processInfo.systemUptime
                var interval = now - lastTime
                if let start = previous?.captureTime, let end = sample.captureTime {
                    interval = end - start
                    if interval < -86_300 { interval += 86_400 } // Midnight
                }
                let rows = sample.rates(since: previous, seconds: interval)
                let time = Date()
                let observed = history.observe(rows, at: time)
                let connections = history.entries
                let findings = inspection.inspect(rows, at: time)
                let logError: String?
                do {
                    try self.log.record(observed, findings: findings, at: time)
                    logError = nil
                } catch {
                    logError = "Log write failed. " + error.localizedDescription
                }
                let note = previous == nil ? "Measuring traffic…" : "Updated at " + Self.clock.string(from: time)
                DispatchQueue.main.async {
                    self.applySample(rows)
                    self.connections = connections
                    self.addFindings(findings)
                    self.status = note
                    self.logError = logError
                    self.onChange?()
                }
                previous = sample
                sample = Snapshot()
                lastTime = now
            }
            let message = diagnostic.isEmpty ? "Monitoring stopped. Run topp again from Terminal." : diagnostic
            do { try self.log.finish(at: Date()) }
            catch { DispatchQueue.main.async { self.logError = "Log write failed. " + error.localizedDescription } }
            DispatchQueue.main.async {
                self.applySample([:])
                self.samplerStopped = true
                self.status = message
                self.onChange?()
            }
        }
    }

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.locale = displayLocale
        f.timeStyle = .medium
        return f
    }()
}

private let changeColor = NSColor.systemOrange.withAlphaComponent(0.38)

final class ProcessArtwork {
    let icon: NSImage
    let bundle: Bundle?
    let executable: String?
    lazy var menuIcon: NSImage = {
        let image = icon.copy() as! NSImage
        image.size = NSSize(width: 16, height: 16)
        return image
    }()

    private static let cache: NSCache<NSString, ProcessArtwork> = {
        let cache = NSCache<NSString, ProcessArtwork>()
        cache.countLimit = 256
        return cache
    }()

    static func forRow(_ row: PortRow) -> ProcessArtwork {
        let key = "\(row.id.pid)|\(row.metadata.started?.timeIntervalSince1970 ?? 0)|\(row.metadata.path ?? "")|\(row.process)" as NSString
        if let cached = cache.object(forKey: key) { return cached }
        let artwork = ProcessArtwork(row)
        cache.setObject(artwork, forKey: key)
        return artwork
    }

    private init(_ row: PortRow) {
        let app = pid_t(exactly: row.id.pid).flatMap { $0 > 0 ? NSRunningApplication(processIdentifier: $0) : nil }
        executable = row.metadata.path ?? app?.executableURL?.path
        // For a helper nested inside a .app, use the enclosing application's icon.
        let components = executable.map { URL(fileURLWithPath: $0).pathComponents } ?? []
        let enclosingApp = components.firstIndex { $0.lowercased().hasSuffix(".app") }.map {
            URL(fileURLWithPath: NSString.path(withComponents: Array(components[...$0])))
        }
        let bundleURL = enclosingApp ?? app?.bundleURL
        bundle = bundleURL.flatMap { Bundle(url: $0) }
        if let bundleURL {
            icon = NSWorkspace.shared.icon(forFile: bundleURL.path)
        } else if let path = executable {
            icon = NSWorkspace.shared.icon(forFile: path)
        } else {
            icon = app?.icon ?? NSImage(systemSymbolName: "gearshape", accessibilityDescription: nil)!
        }
    }
}

private struct ProcessDetails: View {
    let row: PortRow
    let artwork: ProcessArtwork

    private func field(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label).foregroundStyle(.secondary).frame(width: 84, alignment: .leading)
            Text(verbatim: value).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 10) {
                Image(nsImage: artwork.icon).resizable().scaledToFit().frame(width: 32, height: 32).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: row.process).font(.headline).textSelection(.enabled)
                    Text("PID \(String(row.id.pid)) · \(row.id.port.label)").foregroundStyle(.secondary)
                }
            }
            Divider()
            if let bundle = artwork.bundle {
                let name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                    ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String
                    ?? bundle.bundleURL.deletingPathExtension().lastPathComponent
                field("Application", name)
                if let id = bundle.bundleIdentifier { field("Bundle ID", id) }
            }
            if let uid = row.metadata.user {
                let name = getpwuid(uid).map { String(cString: $0.pointee.pw_name) }
                field("User", name.map { "\($0) (UID \(uid))" } ?? "UID \(uid)")
            }
            if let parent = row.metadata.parent {
                field("Parent process", "PID \(parent)")
            }
            if let start = row.metadata.started {
                field("Started", start.formatted(Date.FormatStyle(date: .abbreviated, time: .standard, locale: displayLocale)))
            }
            field("Executable", artwork.executable ?? "Path unavailable")
        }
        .font(.callout).padding(14).frame(width: 380, alignment: .leading)
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct ProcessInfoButton: NSViewRepresentable {
    let row: PortRow
    func makeCoordinator() -> Coordinator { Coordinator(row: row) }

    func makeNSView(context: Context) -> NSButton {
        let icon = NSImage(systemSymbolName: "info.circle", accessibilityDescription: nil)!
        let button = NSButton(image: icon, target: context.coordinator, action: #selector(Coordinator.show(_:)))
        button.isBordered = false
        button.imagePosition = .imageOnly
        return button
    }

    func updateNSView(_ button: NSButton, context: Context) {
        let coordinator = context.coordinator
        if coordinator.row.id != row.id || coordinator.row.metadata.started != row.metadata.started
            || coordinator.row.process != row.process || coordinator.row.metadata.path != row.metadata.path {
            coordinator.popover?.close()
        }
        coordinator.row = row
        let label = "Process information for \(row.process) (PID \(row.id.pid))"
        button.toolTip = label
        button.setAccessibilityLabel(label)
    }

    static func dismantleNSView(_ view: NSButton, coordinator: Coordinator) { coordinator.popover?.close() }

    final class Coordinator: NSObject {
        var row: PortRow
        var popover: NSPopover?
        init(row: PortRow) { self.row = row }

        @objc func show(_ sender: NSButton) {
            if let popover, popover.isShown { popover.performClose(sender); return }
            let details = ProcessDetails(row: row, artwork: ProcessArtwork.forRow(row))
            let host = NSHostingController(rootView: details)
            let popover = NSPopover()
            popover.behavior = .transient
            popover.contentViewController = host
            popover.contentSize = host.view.fittingSize
            self.popover = popover
            popover.show(relativeTo: sender.bounds, of: sender, preferredEdge: .maxY)
        }
    }
}

// Store the snapshot on the rendered row so sorting, filtering and sample updates
// cannot accidentally target a different process via a stale table index.
private struct RowMenuAnchor: NSViewRepresentable {
    let makeMenu: () -> NSMenu

    final class AnchorView: NSView {
        var makeMenu: (() -> NSMenu)?
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }

    func makeNSView(context: Context) -> AnchorView { AnchorView() }
    func updateNSView(_ view: AnchorView, context: Context) { view.makeMenu = makeMenu }
}

private final class NetworkWindow: NSWindow {
    func rowMenu(at locationInWindow: NSPoint) -> NSMenu? {
        guard let contentView, let parent = contentView.superview else { return nil }
        var hit = contentView.hitTest(parent.convert(locationInWindow, from: nil))
        while let view = hit {
            if let table = view as? NSTableView {
                let row = table.row(at: table.convert(locationInWindow, from: nil))
                guard row >= 0, let rowView = table.rowView(atRow: row, makeIfNecessary: false) else { return nil }
                if let anchor = anchor(in: rowView) { return anchor.makeMenu?() }
                // The column containing the anchor can be scrolled out of view.
                for column in 0..<table.numberOfColumns {
                    if let cell = table.view(atColumn: column, row: row, makeIfNecessary: true),
                       let anchor = anchor(in: cell) { return anchor.makeMenu?() }
                }
                return nil
            }
            hit = view.superview
        }
        return nil
    }

    private func anchor(in view: NSView) -> RowMenuAnchor.AnchorView? {
        if let anchor = view as? RowMenuAnchor.AnchorView { return anchor }
        for child in view.subviews {
            if let anchor = anchor(in: child) { return anchor }
        }
        return nil
    }

    override func sendEvent(_ event: NSEvent) {
        if event.type == .rightMouseDown || (event.type == .leftMouseDown && event.modifierFlags.contains(.control)),
           let view = contentView, let menu = rowMenu(at: event.locationInWindow) {
            NSMenu.popUpContextMenu(menu, with: event, for: view)
            return
        }
        super.sendEvent(event)
    }
}

private enum MonitorTab: String, CaseIterable {
    case ports = "Live ports"
    case connections = "Recent connections"
    case findings = "Findings"
}

private final class RowMenuItem: NSMenuItem {
    private let performAction: () -> Void

    init(_ title: String, enabled: Bool = true, perform: @escaping () -> Void) {
        performAction = perform
        super.init(title: title, action: #selector(invoke), keyEquivalent: "")
        target = self
        isEnabled = enabled
    }

    required init(coder: NSCoder) { fatalError("RowMenuItem is created programmatically") }
    @objc private func invoke() { performAction() }
}

struct PortWindow: View {
    @ObservedObject var monitor: Monitor
    static let size = NSSize(width: 1060, height: 540)
    // Total width of the Port, Protocol, PID, Inbound, and Outbound columns,
    // which grow with the text. Process and State absorb the remaining width.
    static let scaledColumnsWidth: CGFloat = 65 * 3 + 89 * 2
    private var scale: CGFloat { monitor.fontSize / Monitor.defaultFontSize }

    private func copy(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }

    private func showError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "OK")
        if let window = NSApp.mainWindow { alert.beginSheetModal(for: window) }
        else { alert.runModal() }
    }

    private func confirmTermination(_ target: ProcessTarget) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Terminate \(target.name) (PID \(target.pid))?"
        alert.informativeText = "This sends a termination request to the entire process. Its other connections and unsaved work may be affected."
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Terminate Process").hasDestructiveAction = true
        let respond: (NSApplication.ModalResponse) -> Void = { response in
            guard response == .alertSecondButtonReturn else { return }
            do {
                try target.requestTermination()
                let notice = "Termination requested for \(target.name) (PID \(target.pid))."
                monitor.actionNotice = notice
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak monitor = self.monitor] in
                    if monitor?.actionNotice == notice { monitor?.actionNotice = nil }
                }
            } catch {
                self.showError(error.localizedDescription)
            }
        }
        if let window = NSApp.mainWindow { alert.beginSheetModal(for: window, completionHandler: respond) }
        else { respond(alert.runModal()) }
    }

    private func processMenu(_ target: ProcessTarget, addContext: (NSMenu) -> Void) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        let heading = NSMenuItem(title: "\(target.name) · PID \(target.pid)", action: nil, keyEquivalent: "")
        heading.isEnabled = false
        menu.addItem(heading)
        let path = target.metadata.path
        menu.addItem(RowMenuItem("Reveal Executable in Finder", enabled: path.map(FileManager.default.fileExists(atPath:)) == true) {
            guard let path, NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "") else {
                self.showError("Finder could not reveal the recorded executable.")
                return
            }
        })
        menu.addItem(RowMenuItem("Copy Executable Path", enabled: path != nil) { if let path { self.copy(path) } })
        menu.addItem(RowMenuItem("Copy PID") { self.copy(String(target.pid)) })
        menu.addItem(.separator())
        addContext(menu)
        menu.addItem(.separator())
        menu.addItem(RowMenuItem("Terminate Process…", enabled: target.canRequestTermination) {
            self.confirmTermination(target)
        })
        return menu
    }

    private func searchConnections(_ name: String) {
        monitor.query = name
        monitor.tab = .connections
    }

    fileprivate func portMenu(_ row: PortRow) -> NSMenu {
        let target = ProcessTarget(pid: row.id.pid, name: row.process, metadata: row.metadata)
        return processMenu(target) { menu in
            let peers = Set(row.sockets.filter { !$0.remote.isWildcard }.map { $0.remote.display }).sorted()
            menu.addItem(RowMenuItem(peers.count > 1 ? "Copy Remote Endpoints" : "Copy Remote Endpoint",
                                     enabled: !peers.isEmpty) { self.copy(peers.joined(separator: "\n")) })
            menu.addItem(RowMenuItem("Search Connections by Process Name") { self.searchConnections(row.process) })
            menu.addItem(RowMenuItem("Hide \(row.id.port.label)") {
                self.monitor.saveHidden(self.monitor.hidden.union([row.id.port.label]))
            })
        }
    }

    fileprivate func connectionMenu(_ entry: ConnectionHistory.Entry) -> NSMenu {
        let target = ProcessTarget(pid: entry.pid, name: entry.process, metadata: entry.metadata)
        return processMenu(target) { menu in
            menu.addItem(RowMenuItem("Copy Local Endpoint") { self.copy(entry.id.local.display) })
            menu.addItem(RowMenuItem("Copy Remote Endpoint") { self.copy(entry.remote.display) })
        }
    }

    private func findingMenu(_ finding: Finding) -> NSMenu {
        let target = ProcessTarget(pid: finding.pid, name: finding.process, metadata: finding.metadata)
        return processMenu(target) { menu in
            menu.addItem(RowMenuItem("Copy Finding") {
                self.copy("\(finding.time.formatted(date: .abbreviated, time: .standard)) · \(finding.process) (PID \(finding.pid))\n\(finding.title)\n\(finding.detail)")
            })
            menu.addItem(RowMenuItem("Search Connections by Process Name") { self.searchConnections(finding.process) })
        }
    }

    private var terms: [String] { monitor.query.split(whereSeparator: \.isWhitespace).map(String.init) }

    private var matches: [PortRow] {
        let words = terms
        return monitor.visible.filter { row in
            guard !words.isEmpty else { return true }
            let sockets = row.sockets.map { "\($0.local.display) \($0.remote.display)" }.joined(separator: " ")
            let text = "\(row.id.port.label) \(row.process) \(row.id.pid) \(row.state) \(row.metadata.path ?? "") \(sockets)"
            return words.allSatisfy { text.localizedCaseInsensitiveContains($0) }
        }
    }

    private var connections: [ConnectionHistory.Entry] {
        let words = terms
        let entries = monitor.visibleConnections
        guard !words.isEmpty else { return entries }
        return entries.filter { entry in
            let text = "\(entry.process) \(entry.pid) \(entry.transport) \(entry.id.local.display) \(entry.remote.display) \(entry.states)"
            return words.allSatisfy { text.localizedCaseInsensitiveContains($0) }
        }
    }

    private var findings: [Finding] {
        let words = terms
        let entries = monitor.visibleFindings
        guard !words.isEmpty else { return entries }
        return entries.filter { finding in
            let text = "\(finding.title) \(finding.detail) \(finding.process) \(finding.pid)"
            return words.allSatisfy { text.localizedCaseInsensitiveContains($0) }
        }
    }

    private func cell(_ value: String, changed: Bool) -> some View {
        Text(value)
            .padding(.horizontal, 3)
            .background(changed ? Color(nsColor: changeColor) : .clear,
                        in: RoundedRectangle(cornerRadius: 3))
    }

    private var portControls: some View {
        HStack {
            Button("Hide Selected Ports") {
                let selected = matches.filter { monitor.selection.contains($0.id) }.map { $0.id.port.label }
                monitor.saveHidden(monitor.hidden.union(selected))
                monitor.selection.removeAll()
            }
            .disabled(!matches.contains { monitor.selection.contains($0.id) })
            .help("Hide the selected ports and protocols for all processes.")
            Menu("Hidden (\(monitor.hidden.count))") {
                ForEach(monitor.hidden.sorted(), id: \.self) { port in
                    Button("Show \(port)") { monitor.saveHidden(monitor.hidden.subtracting([port])) }
                }
                Divider()
                Button("Show All") { monitor.saveHidden([]) }
            }
            .fixedSize()
            .disabled(monitor.hidden.isEmpty)
        }
    }

    private func portsTable(_ rows: [PortRow]) -> some View {
        Table(rows, selection: $monitor.selection, sortOrder: $monitor.sortOrder) {
            TableColumn("Port", value: \.id.port.number) { row in
                Text(String(row.id.port.number)).monospacedDigit()
                    .background(RowMenuAnchor { portMenu(row) })
            }.width(65 * scale)
            TableColumn("Protocol") { Text($0.id.port.transport) }.width(65 * scale)
            TableColumn("Process", value: \.process) { row in
                HStack(spacing: 4) {
                    Image(nsImage: ProcessArtwork.forRow(row).icon)
                        .resizable().scaledToFit().frame(width: 18 * scale, height: 18 * scale).accessibilityHidden(true)
                    cell(row.process, changed: row.changed.contains(.process)).lineLimit(1).help(row.process)
                    Spacer(minLength: 0)
                    ProcessInfoButton(row: row).frame(width: 20, height: 20)
                }
            }.width(min: 145, ideal: 200)
            TableColumn("PID") { Text(String($0.id.pid)).monospacedDigit() }.width(65 * scale)
            TableColumn("State", value: \.state) { cell($0.state, changed: $0.changed.contains(.state)) }.width(min: 95, ideal: 140)
            TableColumn("Remote peer") { row in
                let peers = Set(row.sockets.filter { !$0.remote.isWildcard }.map { $0.remote.display })
                Text(verbatim: peers.count > 1 ? "\(peers.count) peers" : peers.first ?? "—")
                    .lineLimit(1).help(peers.sorted().joined(separator: "\n"))
            }.width(min: 100, ideal: 155)
            TableColumn("↓ Inbound") { cell($0.rxText, changed: $0.changed.contains(.rx)).monospacedDigit() }.width(89 * scale)
            TableColumn("↑ Outbound") { cell($0.txText, changed: $0.changed.contains(.tx)).monospacedDigit() }.width(89 * scale)
        }
        // Rebuild the table so row heights and column widths follow the new size.
        .id(monitor.fontSize)
    }

    private func connectionsTable(_ entries: [ConnectionHistory.Entry]) -> some View {
        Table(entries) {
            TableColumn("Last seen") { entry in
                Text(entry.lastSeen.formatted(date: .omitted, time: .standard)).monospacedDigit()
                    .background(RowMenuAnchor { connectionMenu(entry) })
                    .help("First seen " + entry.firstSeen.formatted(date: .abbreviated, time: .standard)
                          + "\nLast seen " + entry.lastSeen.formatted(date: .abbreviated, time: .standard))
            }.width(min: 90, ideal: 112)
            TableColumn("Process") { Text(verbatim: $0.process).help($0.process) }
            TableColumn("PID") { Text(String($0.pid)) }.width(65 * scale)
            TableColumn("Protocol") { Text($0.transport) }.width(65 * scale)
            TableColumn("Local endpoint") { endpointCell($0.id.local) }.width(min: 130, ideal: 172)
            TableColumn("Remote peer") { endpointCell($0.remote) }.width(min: 140, ideal: 180)
            TableColumn("Last state") { Text(verbatim: $0.states) }
        }
        .id(monitor.fontSize)
    }

    private func endpointCell(_ endpoint: SocketEndpoint) -> some View {
        Text(verbatim: endpoint.display).lineLimit(1).help(endpoint.display)
    }

    private func emptyMessage(_ message: String) -> some View {
        Text(message).foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder private func findingList(_ items: [Finding]) -> some View {
        if items.isEmpty {
            emptyMessage(monitor.findings.isEmpty ? "No findings observed this session." : "No findings match the current filters.")
        } else {
            let font = Font.system(size: monitor.fontSize)
            List(items) { finding in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(verbatim: finding.title).font(font.bold())
                        Spacer()
                        Text(finding.time.formatted(date: .omitted, time: .standard)).font(font).foregroundStyle(.secondary)
                            .help(finding.time.formatted(date: .abbreviated, time: .standard))
                    }
                    Text(verbatim: "\(finding.process) · PID \(finding.pid)").font(font.weight(.medium))
                    Text(verbatim: finding.detail).font(font).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .textSelection(.enabled).padding(.vertical, 4)
                .contentShape(Rectangle())
                .background(RowMenuAnchor { findingMenu(finding) })
            }
            .id(monitor.fontSize)
        }
    }

    @ViewBuilder private var findingNotice: some View {
        let unread = monitor.unreadFindings
        if let latest = unread.first {
            let label = unread.count == 1 ? "1 new finding" : "\(unread.count) new findings"
            Button(action: monitor.reviewNewFindings) {
                HStack(spacing: 8) {
                    Image(systemName: "bell.badge.fill").foregroundStyle(.orange)
                    Text(label).bold().fixedSize()
                    Text(verbatim: "\(latest.title) · \(latest.process)")
                        .lineLimit(1).truncationMode(.tail)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.right").foregroundStyle(.secondary)
                }
                .padding(.horizontal, 12).padding(.vertical, 7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.13))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(label). \(latest.title), \(latest.process)")
            .accessibilityHint("Review findings")
            .help("Review new findings")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Picker("View", selection: $monitor.tab) {
                    ForEach(MonitorTab.allCases, id: \.self) { page in
                        let count = monitor.visibleFindings.count
                        Text(page == .findings && count > 0 ? "Findings (\(count))" : page.rawValue).tag(page)
                    }
                }.pickerStyle(.segmented).labelsHidden().fixedSize()
                Spacer()
                if monitor.tab == .ports { portControls }
            }.padding(.horizontal, 12).padding(.top, 10)
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search process, IP, port, or activity", text: $monitor.query)
                    .textFieldStyle(.roundedBorder).frame(maxWidth: 360)
                Button {
                    monitor.query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .frame(width: 22, height: 22)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear search")
                .help("Clear search")
                .disabled(monitor.query.isEmpty)
                Toggle("Hide Apple-signed apps", isOn: $monitor.hideAppleSigned)
                    .toggleStyle(.checkbox)
                    .help("Hide verified Apple executables, including system tools. All activity is still logged.")
            }.padding(.horizontal, 12).padding(.vertical, 8)
            Divider()
            if monitor.tab != .findings { findingNotice }
            switch monitor.tab {
            case .ports:
                portsTable(matches)
            case .connections:
                let entries = connections
                if entries.isEmpty {
                    emptyMessage(monitor.connections.isEmpty ? "Waiting for a socket with a remote peer…" : "No connections match the current filters.")
                } else { connectionsTable(entries) }
            case .findings:
                let items = findings
                let reviewIDs = monitor.windowIsKey ? Set(items.map(\.id)) : []
                findingList(items)
                    .task(id: reviewIDs) {
                        guard !Task.isCancelled, monitor.windowIsKey, monitor.tab == .findings else { return }
                        monitor.markFindingsReviewed(reviewIDs)
                    }
            }
            Divider()
            HStack {
                switch monitor.tab {
                case .ports:
                    let portCount = Set(matches.map { $0.id.port }).count
                    let processCount = Set(matches.map { $0.id.pid }).count
                    Text("\(portCount) \(portCount == 1 ? "port" : "ports") · \(processCount) \(processCount == 1 ? "process" : "processes")")
                case .connections:
                    Text("Showing \(connections.count) · Last 300 observed connections")
                case .findings:
                    Text("Showing \(findings.count) · Last 200 findings this session")
                }
                Spacer()
                let status = monitor.logError ?? monitor.actionNotice ?? monitor.status
                Text(status).lineLimit(2)
                    .foregroundStyle(monitor.logError == nil ? Color.secondary : .orange)
                    .help(status)
                Button("Show logs") {
                    NSWorkspace.shared.activateFileViewerSelecting([SessionLog.fileURL])
                }
                .disabled(!FileManager.default.fileExists(atPath: SessionLog.fileURL.path))
                .help(SessionLog.fileURL.path)
            }.font(.system(size: monitor.fontSize - 3)).foregroundStyle(.secondary).padding(.horizontal, 12).padding(.vertical, 7)
        }
        .font(.system(size: monitor.fontSize))
        .frame(minWidth: 800, minHeight: 320)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    private static let readoutFont = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
    private static let readoutWidth: CGFloat = {
        let field = String(repeating: "8", count: MenuBarSnapshot.rateCharacterLimit)
        let sample = "↓\(field) ↑\(field)" as NSString
        return ceil(sample.size(withAttributes: [.font: readoutFont]).width) + 16
    }()
    private static let networkIcon = NSImage(systemSymbolName: "network", accessibilityDescription: nil)
    private static let pendingIcon = NSImage(systemSymbolName: "bell.badge.fill", accessibilityDescription: nil)
    let menuMode: Bool
    let monitor: Monitor
    var window: NSWindow?
    var item: NSStatusItem?
    fileprivate let summary = NSMenu()
    private let findingsItem = NSMenuItem()
    private let markReviewedItem = NSMenuItem()
    private let totalsItem = NSMenuItem()
    private var trackingMenu = false
    private var trafficItems = [NSMenuItem]()
    private var menuProcesses = [MenuProcessTraffic]()

    init(menuMode: Bool, monitor: Monitor = Monitor()) {
        self.menuMode = menuMode
        self.monitor = monitor
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let main = NSMenu()
        let appMenu = NSMenu()
        add("Quit topp", to: appMenu, action: #selector(quit), key: "q")
        main.addItem(withTitle: "topp", action: nil, keyEquivalent: "").submenu = appMenu
        let edit = NSMenu(title: "Edit")
        for (label, key, action) in [("Cut", "x", "cut:"), ("Copy", "c", "copy:"), ("Paste", "v", "paste:"), ("Select All", "a", "selectAll:")] {
            edit.addItem(withTitle: label, action: NSSelectorFromString(action), keyEquivalent: key)
        }
        main.addItem(withTitle: edit.title, action: nil, keyEquivalent: "").submenu = edit
        let view = NSMenu(title: "View")
        add("Zoom In", to: view, action: #selector(zoomIn), key: "+")
        // ⌘= is the same key as ⌘+ without Shift.
        add("Zoom In", to: view, action: #selector(zoomIn), key: "=")
        view.items.last?.isHidden = true
        view.items.last?.allowsKeyEquivalentWhenHidden = true
        add("Zoom Out", to: view, action: #selector(zoomOut), key: "-")
        add("Actual Size", to: view, action: #selector(actualSize), key: "0")
        main.addItem(withTitle: view.title, action: nil, keyEquivalent: "").submenu = view
        let windows = NSMenu(title: "Window")
        windows.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        main.addItem(withTitle: windows.title, action: nil, keyEquivalent: "").submenu = windows
        NSApp.mainMenu = main

        let status = NSStatusBar.system.statusItem(withLength: monitor.menuBarIconOnly ? NSStatusItem.squareLength : Self.readoutWidth)
        item = status
        if let button = status.button {
            button.target = self
            button.action = #selector(clickStatus)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        configureStatusMenu()
        monitor.onChange = { [weak self] in self?.updateStatusItem() }
        updateStatusItem()
        if !menuMode { openWindow() }
        monitor.start()
    }

    private func add(_ title: String, to menu: NSMenu, action: Selector, key: String = "") {
        menu.addItem(withTitle: title, action: action, keyEquivalent: key).target = self
    }

    fileprivate func configureStatusMenu() {
        summary.autoenablesItems = false
        summary.delegate = self
        findingsItem.target = self
        findingsItem.action = #selector(openFindings)
        findingsItem.image = NSImage(systemSymbolName: "bell", accessibilityDescription: nil)
        summary.addItem(findingsItem)
        markReviewedItem.title = "Mark Findings as Reviewed"
        markReviewedItem.action = #selector(markFindingsReviewed)
        markReviewedItem.target = self
        summary.addItem(markReviewedItem)
        add("Open Window", to: summary, action: #selector(openWindow))
        summary.addItem(.separator())
        totalsItem.isEnabled = false
        summary.addItem(totalsItem)
        let heading = NSMenuItem(title: "Most active processes", action: nil, keyEquivalent: "")
        heading.isEnabled = false
        summary.addItem(heading)
        for _ in 0..<5 {
            let line = NSMenuItem()
            line.action = #selector(showProcessPorts(_:))
            line.target = self
            summary.addItem(line)
            trafficItems.append(line)
        }
        summary.addItem(.separator())
        add("Quit topp", to: summary, action: #selector(quit))
    }

    @objc private func showProcessPorts(_ sender: NSMenuItem) {
        guard let query = sender.representedObject as? String else { return }
        monitor.tab = .ports
        monitor.query = query
        openWindow()
    }

    @objc func openWindow() {
        if window == nil {
            let w = NetworkWindow(contentRect: NSRect(origin: .zero, size: PortWindow.size),
                             styleMask: [.titled, .resizable, .closable, .miniaturizable],
                             backing: .buffered, defer: false)
            w.title = "topp · Network Ports"
            w.contentView = NSHostingView(rootView: PortWindow(monitor: monitor))
            w.setContentSize(PortWindow.size)
            w.contentMinSize = NSSize(width: 800, height: 320)
            w.isReleasedWhenClosed = false
            w.delegate = self
            w.center()
            window = w
            fitWindowToText(animate: false)
        }
        if window?.isMiniaturized == true { window?.deminiaturize(nil) }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    @objc func clickStatus() {
        guard let button = item?.button else { return }
        let event = NSApp.currentEvent
        if event?.type == .rightMouseUp || event?.modifierFlags.contains(.control) == true {
            updateSummary(monitor.menuBarSnapshot)
            summary.popUp(positioning: nil, at: NSPoint(x: 0, y: -3), in: button)
        } else {
            toggleMenuBarReadout()
        }
    }

    fileprivate func toggleMenuBarReadout() {
        monitor.menuBarIconOnly.toggle()
    }

    @objc func openFindings() {
        monitor.reviewNewFindings()
        openWindow()
    }

    @objc func markFindingsReviewed() {
        monitor.markFindingsReviewed(Set(monitor.unreadFindings.map(\.id)))
    }

    func windowDidBecomeKey(_ notification: Notification) { monitor.windowIsKey = true }
    func windowDidResignKey(_ notification: Notification) { monitor.windowIsKey = false }

    func menuWillOpen(_ menu: NSMenu) { trackingMenu = true }
    func menuDidClose(_ menu: NSMenu) {
        trackingMenu = false
        menuProcesses.removeAll()
    }

    fileprivate func updateSummary(_ snapshot: MenuBarSnapshot) {
        let unread = monitor.unreadFindings.count
        markReviewedItem.isEnabled = unread > 0
        findingsItem.title = unread == 0 ? "Review findings" : "Review findings (\(unread) new)"
        totalsItem.title = monitor.samplerStopped ? monitor.status : "Visible traffic    \(snapshot.summary)"

        // Keep click targets in place while the menu tracks the pointer.
        if !trackingMenu || menuProcesses.isEmpty {
            menuProcesses = Array(snapshot.processes.prefix(trafficItems.count))
        }
        let current = Dictionary(uniqueKeysWithValues: snapshot.processes.map { ($0.id, $0) })
        for (i, item) in trafficItems.enumerated() {
            item.isHidden = i >= menuProcesses.count
            guard !item.isHidden else { continue }
            let process = menuProcesses[i]
            let active = current[process.id]
            item.title = "\(process.name)    ↓ \(active?.rxText ?? "—")    ↑ \(active?.txText ?? "—")"
            item.image = ProcessArtwork.forRow(process.representative).menuIcon
            item.toolTip = "Show live ports for \(process.name) (PID \(process.pid))"
            item.representedObject = "\(process.name) \(process.pid)"
            item.isEnabled = active != nil
        }
        if menuProcesses.isEmpty, let first = trafficItems.first {
            first.title = monitor.rows.isEmpty ? monitor.status : "No measured traffic on visible ports"
            first.image = nil
            first.toolTip = nil
            first.representedObject = nil
            first.isEnabled = false
            first.isHidden = false
        }
    }

    fileprivate func updateStatusItem() {
        guard let item, let button = item.button else { return }
        let snapshot = monitor.menuBarSnapshot
        let iconOnly = monitor.menuBarIconOnly
        let unread = monitor.unreadFindings
        let count = unread.count
        let width = count > 0 ? NSStatusItem.variableLength : (iconOnly ? NSStatusItem.squareLength : Self.readoutWidth)
        if item.length != width { item.length = width }
        func field(_ text: String) -> String {
            String(repeating: " ", count: max(0, MenuBarSnapshot.rateCharacterLimit - text.count)) + text
        }
        let speeds = iconOnly ? "" : "↓\(field(snapshot.downloadText)) ↑\(field(snapshot.uploadText))"
        button.font = Self.readoutFont
        if count > 0 {
            button.image = Self.pendingIcon
            button.imagePosition = .imageLeading
            button.title = iconOnly ? String(count) : "\(count)  \(speeds)"
        } else {
            button.image = iconOnly ? Self.networkIcon : nil
            button.imagePosition = iconOnly ? .imageOnly : .noImage
            button.title = speeds
        }
        var hints = [snapshot.accessibilitySummary, count == 1 ? "1 new finding" : "\(count) new findings"]
        if let latest = unread.first { hints.append("\(latest.title) · \(latest.process)") }
        if monitor.samplerStopped || monitor.rows.isEmpty { hints.append(monitor.status) }
        if let top = snapshot.processes.first { hints.append("Most active: \(top.name) (PID \(top.pid))") }
        if let error = monitor.logError { hints.append(error) }
        button.setAccessibilityLabel((["topp"] + hints).joined(separator: ". "))
        let clickHint = iconOnly ? "Click to show speeds" : "Click to show only the icon"
        button.toolTip = (hints + [clickHint + " · Right-click to open the menu"]).joined(separator: "\n")
        if trackingMenu { updateSummary(snapshot) }
    }

    @objc func zoomIn() {
        monitor.zoom(by: 1)
        fitWindowToText(animate: true)
    }
    @objc func zoomOut() { monitor.zoom(by: -1) }
    @objc func actualSize() { monitor.fontSize = Monitor.defaultFontSize }

    // Widen the window, never narrow it, so larger text keeps every column visible.
    private func fitWindowToText(animate: Bool) {
        guard let window, let visible = (window.screen ?? NSScreen.main)?.visibleFrame else { return }
        let scale = monitor.fontSize / Monitor.defaultFontSize
        let needed = PortWindow.size.width + PortWindow.scaledColumnsWidth * (scale - 1)
        var frame = window.frame
        guard frame.width < needed else { return }
        frame.size.width = min(needed, visible.width)
        frame.origin.x = max(visible.minX, min(frame.minX, visible.maxX - frame.width))
        window.setFrame(frame, display: true, animate: animate)
    }

    @objc func quit() { NSApp.terminate(nil) }
    func applicationWillTerminate(_ notification: Notification) {
        do { try monitor.log.finish(at: Date()) }
        catch { FileHandle.standardError.write(Data(("topp: log write failed. " + error.localizedDescription + "\n").utf8)) }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { !menuMode }
}

struct LaunchError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

// sudo shares the foreground process group for its password prompt. The menu
// process gets a separate session so closing the terminal cannot stop the GUI.
func spawn(_ arguments: [String], input: Int32? = nil, output: Int32? = nil, detached: Bool = false) throws -> pid_t {
    var actions: posix_spawn_file_actions_t?, attr: posix_spawnattr_t?
    func check(_ code: Int32) throws {
        if code != 0 { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
    }
    try check(posix_spawn_file_actions_init(&actions))
    defer { posix_spawn_file_actions_destroy(&actions) }
    try check(posix_spawnattr_init(&attr))
    defer { posix_spawnattr_destroy(&attr) }
    let flags = POSIX_SPAWN_CLOEXEC_DEFAULT | (detached ? POSIX_SPAWN_SETSID : 0)
    try check(posix_spawnattr_setflags(&attr, Int16(flags)))
    if let input {
        try check(posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO))
    } else {
        try check(posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0))
    }
    if let output {
        try check(posix_spawn_file_actions_adddup2(&actions, output, STDOUT_FILENO))
    } else {
        try check(posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0))
    }
    if detached {
        try check(posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO))
    } else {
        try check(posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO))
    }
    let argv = arguments.map { strdup($0) } + [nil]
    defer { argv.forEach { free($0) } }
    var pid: pid_t = 0
    try check(posix_spawn(&pid, arguments[0], &actions, &attr, argv, environ))
    return pid
}

func runWindow(menuMode: Bool) {
    let app = NSApplication.shared
    app.setActivationPolicy(menuMode ? .accessory : .regular)
    let delegate = AppDelegate(menuMode: menuMode)
    app.delegate = delegate
    withExtendedLifetime(delegate) { app.run() }
}

let usage = """
Usage: topp [-d | --log-path]
  No options     Inspect live ports, recent connections, and findings for this session.
  -d             Show download (↓) and upload (↑) in KB/s beside the clock.
                 Click to toggle speeds and icon. Right-click to open the window or menu actions.
  -h, --help     Show this help.
  --log-path     Print the path of the persistent JSON Lines event log.
"""
let args = Array(CommandLine.arguments.dropFirst())
do {
    if args == ["--help"] || args == ["-h"] { print(usage); exit(0) }
    if args == ["--log-path"] { print(SessionLog.fileURL.path); exit(0) }
    guard geteuid() != 0 else { throw LaunchError("Run topp as your regular user. It requests sudo when needed.") }
    if args == ["--menu-stream"], isatty(STDIN_FILENO) == 0 { runWindow(menuMode: true); exit(0) }
    guard args.isEmpty || args == ["-d"] else { throw LaunchError(usage) }
    let input = try startCollector()
    if args == ["-d"] {
        guard let path = Bundle.main.executableURL?.path else { throw LaunchError("Could not find the topp executable.") }
        _ = try spawn([path, "--menu-stream"], input: input.fileDescriptor, detached: true)
        print("topp is beside the clock. Click to toggle speeds and icon. Right-click for Open Window, traffic, and findings.")
    } else {
        guard dup2(input.fileDescriptor, STDIN_FILENO) >= 0 else { throw LaunchError("Could not open the nettop data stream.") }
        runWindow(menuMode: false)
    }
} catch {
    FileHandle.standardError.write(Data(("topp: " + error.localizedDescription + "\n").utf8))
    exit(1)
}
