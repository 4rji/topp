#sourceLocation(file: "tests/network.swift", line: 2)
// Fixtures follow nettop -n -x -L 1 -J time,state,bytes_in,bytes_out.
private let processID = 90_000_001
private let fixtureOwner = Owner(port: Port(transport: "TCP", number: 54000), pid: processID)

private func check(_ condition: @autoclosure () -> Bool, _ message: String, file: String = #filePath, line: UInt = #line) {
    guard condition() else {
        FileHandle.standardError.write(Data("FAIL \(file):\(line): \(message)\n".utf8))
        exit(1)
    }
}

private func snapshot(_ sockets: [String], name: String = "Fixture, App", pid: Int = processID) -> Snapshot {
    var sample = Snapshot()
    sample.read("time,,state,bytes_in,bytes_out,")
    sample.read("09:30:01.250,\(name).\(pid),,0,0,")
    for socket in sockets { sample.read("09:30:01.250,\(socket),") }
    return sample
}

private func socket(_ remote: String, rx: Int, tx: Int, port: Int = 54000) -> String {
    "tcp4 192.0.2.7:\(port)<->\(remote),Established,\(rx),\(tx)"
}

private let firstSample = snapshot([socket("203.0.113.8:443", rx: 3000, tx: 4000)])
check(firstSample.hasHeader, "accept a timestamped CSV header")
check(firstSample.captureTime == 34201.25, "parse the capture time")
check(firstSample.rows[fixtureOwner]?.process == "Fixture, App", "preserve commas in process names")
check(firstSample.rates(since: nil, seconds: 1)[fixtureOwner]?.hasRate == false, "initial sample has no rate")

private let nextSample = snapshot([socket("203.0.113.8:443", rx: 3400, tx: 4200),
                                   socket("203.0.113.9:443", rx: 90000, tx: 82000)])
private let rates = nextSample.rates(since: firstSample, seconds: 2)
check(rates[fixtureOwner]?.rx == 200 && rates[fixtureOwner]?.tx == 100,
      "a new peer with large cumulative counters must not inflate the measured traffic")
private let reset = snapshot([socket("203.0.113.8:443", rx: 2, tx: 1)])
private let afterReset = reset.rates(since: nextSample, seconds: 1)
check(afterReset[fixtureOwner]?.rx == 0 && afterReset[fixtureOwner]?.tx == 0, "ignore falling counters")
private let reusedPID = snapshot([socket("203.0.113.8:443", rx: 5000, tx: 5000)], name: "Replacement")
check(reusedPID.rates(since: firstSample, seconds: 1)[fixtureOwner]?.hasRate == false,
      "discard an earlier process's counters when its PID is reused")
private let partial = snapshot(["tcp4 192.0.2.7:54000<->203.0.113.8:443,Established,2000,"])
private let partialRate = firstSample.rates(since: partial, seconds: 2)[fixtureOwner]
check(partialRate?.hasRxRate == true && partialRate?.hasTxRate == false && partialRate?.rx == 500,
      "an absent send counter must not turn the next lifetime total into a measured rate")

private let v6 = snapshot(["tcp6 fe80::91%en0.54000<->2001:db8::37.443,Established,5,7",
                           "udp6 *.5353<->*.*,,0,0"])
private let scoped = v6.rows[fixtureOwner]?.sockets.first
check(scoped?.local.host == "fe80::91%en0" && scoped?.local.port == 54000, "keep IPv6 interface zones")
check(scoped?.remote.host == "2001:db8::37" && scoped?.remote.port == 443, "extract IPv6 peers")
private let mdns = Owner(port: Port(transport: "UDP", number: 5353), pid: processID)
private let wildcard = v6.rows[mdns]?.sockets.first
check(wildcard?.local.isWildcard == true && wildcard?.remote.port == nil, "parse IPv6 wildcard sockets")

private let instant = Date(timeIntervalSince1970: 1_700_000_000)
private func seconds(_ elapsed: Int) -> Date { instant.addingTimeInterval(Double(elapsed)) }

private let listener = snapshot(["tcp4 *:8080<->*:*,Listen,0,0"])
private let loopback = snapshot(["tcp4 127.0.0.1:8080<->*:*,Listen,0,0"])
private var listenerEngine = NetworkInspection()
check(listenerEngine.inspect(listener.rows, at: instant).isEmpty, "existing listeners only seed the baseline")
private var newListenerEngine = NetworkInspection()
check(newListenerEngine.inspect(loopback.rows, at: instant).isEmpty, "loopback baseline")
private let opened = newListenerEngine.inspect(listener.rows, at: seconds(1))
check(opened.count == 1 && opened.first?.title == "New wildcard listener" && opened.first?.pid == processID,
      "identify a newly opened wildcard listener")
check(newListenerEngine.inspect(listener.rows, at: seconds(2)).isEmpty, "avoid repeating an active listener")

private func attempts(_ ports: Range<Int>, host: String = "198.51.100.6") -> Snapshot {
    snapshot(ports.map { "tcp4 192.0.2.7:\(50000 + $0)<->\(host):\($0),SynSent,0,0" })
}
private var attemptEngine = NetworkInspection()
_ = attemptEngine.inspect([:], at: instant)
check(attemptEngine.inspect(attempts(10..<14).rows, at: seconds(1)).isEmpty, "four SYN ports are below threshold")
check(attemptEngine.inspect(attempts(10..<14).rows, at: seconds(2)).isEmpty, "duplicate SYNs are not distinct ports")
check(attemptEngine.inspect(attempts(14..<18).rows, at: seconds(3)).map(\.title) == ["TCP attempts to multiple ports"],
      "accumulate eight distinct destination ports across samples")
check(attemptEngine.inspect(attempts(10..<18).rows, at: seconds(4)).isEmpty, "suppress repeated attempt alerts")
private var expiredEngine = NetworkInspection()
_ = expiredEngine.inspect([:], at: instant)
_ = expiredEngine.inspect(attempts(10..<14).rows, at: seconds(1))
check(expiredEngine.inspect(attempts(14..<18).rows, at: seconds(50)).isEmpty, "expire old SYN observations")
check(expiredEngine.inspect(attempts(10..<20, host: "127.0.0.1").rows, at: seconds(51)).isEmpty,
      "exclude attempts against the Mac's loopback interface")

private func transfer(_ sampleIndex: Int) -> Snapshot {
    snapshot([socket("198.51.100.7:443", rx: 500, tx: sampleIndex * 6_000_000)])
}
private var uploadEngine = NetworkInspection()
var preceding = transfer(0)
_ = uploadEngine.inspect(preceding.rows, at: instant)
for index in 1...3 {
    let current = transfer(index)
    let signals = uploadEngine.inspect(current.rates(since: preceding, seconds: 1), at: seconds(index))
    check(signals.map(\.title) == (index == 3 ? ["Sustained upload"] : []),
          "require three successive high-upload observations, sample \(index)")
    preceding = current
}
private var sharedPortEngine = NetworkInspection()
_ = sharedPortEngine.inspect([:], at: instant)
for index in 1...3 {
    var shared = rates
    shared[fixtureOwner]?.tx = 8_000_000
    check(sharedPortEngine.inspect(shared, at: seconds(index)).isEmpty, "never attribute a shared upload rate to one peer")
}

private var history = ConnectionHistory()
history.observe(firstSample.rows, at: instant)
history.observe(nextSample.rows, at: seconds(1))
check(history.entries.count == 2, "track both peers on a shared local port")
history.observe([:], at: seconds(2))
check(history.entries.count == 2, "retain closed sockets for investigation")
history.observe(firstSample.rows, at: seconds(3))
check(history.entries.first?.remote.host == "203.0.113.8" && history.entries.first?.lastSeen == seconds(3),
      "sort most recently observed peer first")
check(history.entries.first?.process == "Fixture, App" && history.entries.first?.pid == processID,
      "preserve process identity in history")
history.observe(listener.rows, at: seconds(3))
check(history.entries.count == 2, "a wildcard listener has no concrete peer to record")
for n in 1...305 {
    let sample = snapshot([socket("198.51.100.50:\(n)", rx: 0, tx: 0)])
    history.observe(sample.rows, at: seconds(n + 3))
}
check(history.entries.count == 300 && history.entries.first?.remote.port == 305,
      "retain the most recent 300 observations")
print("Passed network parser, traffic rates, findings, and connection history checks.")

private func checkAppleFilter() {
    let suite = "org.4rji.topp.filter-tests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let monitor = Monitor(defaults: defaults)
    check(!monitor.hideAppleSigned, "initially display all processes")
    let apple = snapshot([socket("198.51.100.12:443", rx: 1, tx: 2, port: 51001),
                          "tcp4 *:51001<->*:*,Listen,0,0"], name: "Safari", pid: processID + 1)
    let other = snapshot([socket("198.51.100.33:443", rx: 1, tx: 2, port: 51002),
                          "tcp4 *:51002<->*:*,Listen,0,0"], name: "Safari", pid: processID + 2)
    var appleRow = apple.rows.values.first!
    appleRow.metadata.appleSigned = true
    appleRow.metadata.path = "/fixture/Safari"
    appleRow.metadata.user = 501
    appleRow.metadata.started = instant
    appleRow.tx = 2000
    appleRow.hasTxRate = true
    var otherRow = other.rows.values.first!
    otherRow.tx = 1000
    otherRow.hasTxRate = true
    let rows = [appleRow.id: appleRow, otherRow.id: otherRow]
    monitor.applySample(rows)
    var history = ConnectionHistory(), inspection = NetworkInspection()
    let logged = history.observe(rows, at: instant)
    monitor.connections = history.entries
    _ = inspection.inspect([:], at: instant)
    monitor.findings = inspection.inspect(rows, at: seconds(1))
    let captured = monitor.findings.first { $0.pid == appleRow.id.pid }?.metadata
    check(captured?.path == "/fixture/Safari" && captured?.user == 501 && captured?.started == instant,
          "a finding keeps the executable and process identity from the triggering sample")
    check(monitor.menuBarSnapshot.text == "↓— ↑3", "sum measured uploads before filtering")
    monitor.hideAppleSigned = true
    check(monitor.visible.map(\.id) == [otherRow.id] && monitor.menuBarSnapshot.processes.map(\.pid) == [otherRow.id.pid],
          "filter the port table and menu rows by verified signer even when names match")
    check(monitor.menuBarSnapshot.text == "↓— ↑1", "exclude Apple traffic from the menu-bar totals")
    check(monitor.visibleConnections.map(\.pid) == [otherRow.id.pid] &&
          monitor.visibleFindings.map(\.pid) == [otherRow.id.pid], "filter connection history and findings")
    check(logged.count == 2 && monitor.findings.count == 2, "retain both connections and findings for logging")
    check(Monitor(defaults: defaults).hideAppleSigned, "remember the filter across launches")
    monitor.saveHidden([otherRow.id.port.label])
    check(monitor.visible.isEmpty && monitor.menuBarSnapshot.text == "↓— ↑—", "combine signer filtering with hidden ports")
    monitor.hideAppleSigned = false
    check(monitor.visible.map(\.id) == [appleRow.id] && monitor.visibleConnections.count == 2 &&
          monitor.visibleFindings.count == 2, "restore history while preserving hidden ports")
}
checkAppleFilter()
print("Passed Apple signature display filter checks.")

private func checkUnreadFindings() {
    let suite = "org.4rji.topp.finding-tests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let monitor = Monitor(defaults: defaults)
    func finding(_ process: String, appleSigned: Bool = false) -> Finding {
        Finding(time: instant, process: process, pid: processID, title: "Test", detail: process,
                metadata: ProcessMetadata(appleSigned: appleSigned))
    }
    let first = finding("one"), second = finding("two"), apple = finding("three", appleSigned: true)
    monitor.query = "unrelated ports"
    monitor.hideAppleSigned = true
    monitor.addFindings([first])
    monitor.addFindings([second, apple])
    check(monitor.unreadFindings.map(\.id) == [second.id, first.id], "count new visible findings independently of the port search")
    monitor.reviewNewFindings()
    check(monitor.tab == .findings && monitor.query.isEmpty && monitor.unreadFindings.count == 2,
          "opening review clears the query and waits for findings to be presented")
    monitor.markFindingsReviewed([first.id, apple.id])
    monitor.markFindingsReviewed([first.id])
    check(monitor.unreadFindings.map(\.id) == [second.id] && monitor.findings.count == 3,
          "review visible IDs once while retaining every finding")
    monitor.tab = .ports
    check(monitor.query == "unrelated ports", "return to the search preceding review")
    monitor.hideAppleSigned = false
    check(monitor.unreadFindings.map(\.id) == [second.id, apple.id], "a previously hidden finding remains unread")
    monitor.reviewNewFindings()
    monitor.query = "new process"
    monitor.tab = .connections
    check(monitor.query == "new process", "preserve the explicit process search initiated in Findings")
    monitor.markFindingsReviewed([second.id, apple.id])
    check(monitor.unreadFindings.isEmpty, "the alert clears after all visible findings are reviewed")
    let burst = (0..<205).map { finding(String($0)) }
    monitor.addFindings(burst)
    check(monitor.unreadFindings.map(\.id) == burst.prefix(200).map(\.id),
          "pending findings follow the same 200-event retention as history")
}
checkUnreadFindings()
print("Passed unread finding and review navigation checks.")

private func checkMenuBarDisplay() {
    let suite = "org.4rji.topp.menu-tests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set("port", forKey: "menuBarStyle")
    let monitor = Monitor(defaults: defaults)
    check(!monitor.menuBarIconOnly, "show the directional rates on a fresh launch")
    var refreshes = 0
    monitor.onChange = { refreshes += 1 }
    monitor.menuBarIconOnly = true
    check(refreshes == 1 && Monitor(defaults: defaults).menuBarIconOnly, "refresh and remember the collapsed icon")
    monitor.menuBarIconOnly = false
    check(refreshes == 2 && !Monitor(defaults: defaults).menuBarIconOnly, "restore and remember the expanded rates")
    check(monitor.menuBarSnapshot.text == "↓— ↑—", "an old style preference still opens the numeric indicator")
    check(monitor.menuBarSnapshot.summary == "↓ —   ↑ —", "unmeasured rates are unknown")

    func row(_ port: Int, _ pid: Int, _ rx: Double?, _ tx: Double?) -> PortRow {
        let owner = Owner(port: Port(transport: "TCP", number: port), pid: pid)
        var r = PortRow(id: owner, process: "SameName")
        r.rx = rx ?? 0
        r.tx = tx ?? 0
        r.hasRxRate = rx != nil
        r.hasTxRate = tx != nil
        return r
    }
    let incoming = row(1001, 11, 200, nil)
    let outgoing = row(1002, 11, nil, 300)
    let second = row(1003, 12, 400, nil)
    let idle = row(1004, 13, 0, nil)
    var apple = row(1005, 14, 2000, 2000)
    apple.metadata.appleSigned = true
    monitor.rows = [incoming, outgoing, second, apple, idle]
    monitor.hideAppleSigned = true
    monitor.query = "outside the port search"
    var snapshot = monitor.menuBarSnapshot
    check(snapshot.text == "↓0.6 ↑0.3" && snapshot.summary == "↓ 600 B/s   ↑ 300 B/s", "sum each visible direction independently")
    check(snapshot.accessibilitySummary == "Download 0.6 KB/s, upload 0.3 KB/s", "name arrows and units in hover and VoiceOver text")
    check(snapshot.processes.map(\.pid) == [11, 12], "combine ports of one process and separate different PIDs with identical names")
    check(snapshot.processes.first?.rxText == "200 B/s" && snapshot.processes.first?.txText == "300 B/s", "show both per-process directions")
    check(snapshot.processes.last?.txText == "—", "partial counters are unknown per process")
    monitor.hidden = [incoming.id.port.label, outgoing.id.port.label, second.id.port.label]
    snapshot = monitor.menuBarSnapshot
    check(snapshot.text == "↓0 ↑—" && snapshot.processes.isEmpty && snapshot.summary == "↓ 0 B/s   ↑ —",
          "distinguish idle, hidden and unmeasured traffic")
    check(snapshot.accessibilitySummary == "Download 0 KB/s, upload unavailable", "distinguish an idle direction from a missing counter")
    monitor.hidden = []
    monitor.rows = [row(1010, 11, nil, 1)]
    check(monitor.menuBarSnapshot.text == "↓— ↑0.001", "preserve a measured byte per second")
    monitor.rows = [row(1020, 12, 120_000, 11_000)]
    let notice = Finding(time: instant, process: "Test", pid: 11, title: "Test", detail: "Observed")
    monitor.addFindings([notice])
    check(monitor.menuBarSnapshot.text == "↓120 ↑11" && monitor.unreadFindings.count == 1,
          "findings stay available without replacing the rates")
    monitor.markFindingsReviewed([notice.id])
    check(monitor.menuBarSnapshot.text == "↓120 ↑11", "reviewing findings leaves both directions visible")
    monitor.rows = [row(1020, 12, 5_000_000, 123_456)]
    check(monitor.menuBarSnapshot.text == "↓5000 ↑123.456", "format directional rates without grouping or units")
    monitor.rows = [row(1020, 12, 1_234_567.89, 9_999_999_999.9)]
    let wide = monitor.menuBarSnapshot
    check(wide.downloadText == "1234.57", "reduce decimal places when the integer part widens")
    check(wide.uploadText.count <= MenuBarSnapshot.rateCharacterLimit && Double(wide.uploadText) == 10_000_000,
          "round across a power of ten without overflowing the slot")
    monitor.rows = [row(1020, 12, Double.greatestFiniteMagnitude, nil)]
    check(monitor.menuBarSnapshot.downloadText.count <= MenuBarSnapshot.rateCharacterLimit,
          "the largest finite rate fits in the same slot")
    monitor.samplerStopped = true
    check(monitor.menuBarSnapshot.text == "↓— ↑—" && monitor.menuBarSnapshot.accessibilitySummary == "Download unavailable, upload unavailable",
          "stale measurements after the sampler stops are unavailable")
}
checkMenuBarDisplay()
print("Passed menu bar presentation and measured process traffic checks.")
