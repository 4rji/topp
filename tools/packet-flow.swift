#!/usr/bin/env swift
// Generates the animated README banner: data packets flowing through network cables.
//
//   swift tools/packet-flow.swift --output assets/packet-flow.svg
//   swift tools/packet-flow.swift --traffic traffic.txt --glow 0.6 --output banner.svg
//
// The output is plain SVG with CSS animations, so it also plays inside a GitHub <img>,
// where scripts never run. Each connection is one cable path. Packets on a lane are a
// single dash pattern; every trail layer shares that lane's animated stroke-dashoffset,
// so a lane costs one animation however many packets it carries.
import Foundation

enum Direction: String { case both, outbound, inbound }

struct Options {
    var width = 1280.0
    var height = 360.0
    var background = "#0a0506"
    var color = "#e4002b"          // Packet red.
    var cableColor: String?        // Defaults to a dark shade of the packet color.
    var speed = 170.0              // Pixels per second.
    var direction = Direction.both
    var packetSize = 1.0           // Packet length multiplier.
    var density = 1.0              // Packet frequency multiplier.
    var glow = 1.0                 // Halo strength. 0 turns the halo off.
    var seed: UInt64 = 0x7070
    var traffic: String?           // File with "<label> <rx bytes/s> <tx bytes/s>" per line, or "-".
    var eyebrow = "PORTS · PROCESSES · TRAFFIC"
    var title = "topp"
    var subtitle = "Which process owns each port,|and how much data it moves."
    var output: String?
}

struct Link {
    let label: String
    let rx: Double                 // Inbound bytes per second.
    let tx: Double                 // Outbound bytes per second.
}

let sampleTraffic = [
    Link(label: "TCP 443", rx: 1_850_000, tx: 210_000),
    Link(label: "UDP 443", rx: 640_000, tx: 95_000),
    Link(label: "TCP 22", rx: 38_000, tx: 120_000),
    Link(label: "UDP 5353", rx: 0, tx: 0),
    Link(label: "TCP 5432", rx: 420_000, tx: 980_000),
    Link(label: "TCP 8080", rx: 9_000, tx: 26_000),
    Link(label: "UDP 53", rx: 2_400, tx: 1_100),
    Link(label: "TCP 631", rx: 0, tx: 0),
]

let usage = """
Usage: swift tools/packet-flow.swift [options]
  --output PATH        Write the SVG to PATH instead of standard output.
  --traffic PATH       Read connections from PATH ("-" for standard input). One per line:
                       <label> <rx bytes/s> <tx bytes/s>, for example "TCP 443 1.8M 210K".
                       A connection with no traffic stays dim and stationary.
  --color HEX          Packet color (default #e4002b).
  --cable-color HEX    Cable color (default: dark shade of the packet color).
  --background HEX     Background color (default #0a0506).
  --speed N            Packet speed in pixels per second (default 170).
  --direction MODE     both, outbound, or inbound (default both).
  --packet-size N      Packet length multiplier (default 1).
  --density N          Packet frequency multiplier (default 1).
  --glow N             Halo strength, 0 to disable (default 1).
  --width N, --height N
  --seed N             Change the random layout and timing.
  --eyebrow, --title, --subtitle TEXT
                       Banner text. Separate subtitle lines with "|".
"""

// MARK: Arguments

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("packet-flow: \(message)\n".utf8))
    exit(1)
}

func parseOptions(_ arguments: [String]) -> Options {
    var options = Options()
    var iterator = arguments.makeIterator()
    func value(_ flag: String) -> String {
        guard let next = iterator.next() else { fail("\(flag) needs a value") }
        return next
    }
    func number(_ flag: String) -> Double {
        let text = value(flag)
        guard let parsed = Double(text), parsed.isFinite, parsed >= 0 else { fail("\(flag) needs a number, got \(text)") }
        return parsed
    }
    while let flag = iterator.next() {
        switch flag {
        case "-h", "--help": print(usage); exit(0)
        case "--output": options.output = value(flag)
        case "--traffic": options.traffic = value(flag)
        case "--color": options.color = value(flag)
        case "--cable-color": options.cableColor = value(flag)
        case "--background": options.background = value(flag)
        case "--speed": options.speed = max(1, number(flag))
        case "--packet-size": options.packetSize = max(0.1, number(flag))
        case "--density": options.density = number(flag)
        case "--glow": options.glow = number(flag)
        case "--width": options.width = max(640, number(flag))
        case "--height": options.height = max(200, number(flag))
        case "--seed": options.seed = UInt64(number(flag))
        case "--eyebrow": options.eyebrow = value(flag)
        case "--title": options.title = value(flag)
        case "--subtitle": options.subtitle = value(flag)
        case "--direction":
            let text = value(flag)
            guard let mode = Direction(rawValue: text) else { fail("--direction must be both, outbound, or inbound") }
            options.direction = mode
        default: fail("unknown option \(flag)\n\n\(usage)")
        }
    }
    return options
}

/// Accepts plain bytes per second or a K, M, or G suffix (decimal, like topp's rate column).
func parseRate(_ text: String) -> Double? {
    let scales: [Character: Double] = ["K": 1e3, "M": 1e6, "G": 1e9]
    var body = text.uppercased()
    var scale = 1.0
    if let last = body.last, let factor = scales[last] { scale = factor; body.removeLast() }
    guard let value = Double(body), value.isFinite, value >= 0 else { return nil }
    return value * scale
}

func readTraffic(_ path: String) -> [Link] {
    let data = path == "-" ? FileHandle.standardInput.readDataToEndOfFile() : FileManager.default.contents(atPath: path)
    guard let data, let text = String(data: data, encoding: .utf8) else { fail("cannot read \(path)") }
    var links = [Link]()
    for (index, line) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
        let fields = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
            .split(whereSeparator: \.isWhitespace).map(String.init)
        if fields.isEmpty { continue }
        guard fields.count >= 3, let rx = parseRate(fields[fields.count - 2]), let tx = parseRate(fields[fields.count - 1]) else {
            fail("\(path):\(index + 1): expected <label> <rx bytes/s> <tx bytes/s>")
        }
        links.append(Link(label: fields.dropLast(2).joined(separator: " "), rx: rx, tx: tx))
    }
    guard !links.isEmpty else { fail("\(path) has no connections") }
    return links
}

// MARK: Geometry, color, randomness

struct Point { var x, y: Double }

struct Cubic {
    let p0, p1, p2, p3: Point

    func at(_ t: Double) -> Point {
        let u = 1 - t
        let a = u * u * u, b = 3 * u * u * t, c = 3 * u * t * t, d = t * t * t
        return Point(x: a * p0.x + b * p1.x + c * p2.x + d * p3.x,
                     y: a * p0.y + b * p1.y + c * p2.y + d * p3.y)
    }

    var reversed: Cubic { Cubic(p0: p3, p1: p2, p2: p1, p3: p0) }

    var length: Double {
        var total = 0.0, previous = p0
        for step in 1...512 {
            let point = at(Double(step) / 512)
            total += hypot(point.x - previous.x, point.y - previous.y)
            previous = point
        }
        return total
    }

    var d: String { "M\(n(p0.x)) \(n(p0.y))C\(n(p1.x)) \(n(p1.y)) \(n(p2.x)) \(n(p2.y)) \(n(p3.x)) \(n(p3.y))" }
}

/// Compact number formatting keeps the SVG small.
func n(_ value: Double, _ digits: Int = 1) -> String {
    var text = String(format: "%.\(digits)f", value)
    if text.contains(".") {
        while text.hasSuffix("0") { text.removeLast() }
        if text.hasSuffix(".") { text.removeLast() }
    }
    return text == "-0" ? "0" : text
}

struct RGB {
    var r, g, b: Double

    init(_ r: Double, _ g: Double, _ b: Double) { (self.r, self.g, self.b) = (r, g, b) }

    init(hex: String) {
        var digits = hex.hasPrefix("#") ? String(hex.dropFirst()) : hex
        if digits.count == 3 { digits = digits.map { "\($0)\($0)" }.joined() }
        guard digits.count == 6, let value = UInt32(digits, radix: 16) else { fail("invalid color \(hex)") }
        self.init(Double(value >> 16 & 0xff), Double(value >> 8 & 0xff), Double(value & 0xff))
    }

    func mix(_ other: RGB, _ amount: Double) -> RGB {
        RGB(r + (other.r - r) * amount, g + (other.g - g) * amount, b + (other.b - b) * amount)
    }

    var hex: String {
        String(format: "#%02x%02x%02x", Int(r.rounded()), Int(g.rounded()), Int(b.rounded()))
    }
}

let white = RGB(255, 255, 255), black = RGB(0, 0, 0)

/// SplitMix64: a seeded generator, so the same options always produce the same file.
struct Random {
    var state: UInt64
    mutating func next() -> Double {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return Double((z ^ (z >> 31)) >> 11) / Double(1 << 53)
    }
    mutating func range(_ low: Double, _ high: Double) -> Double { low + (high - low) * next() }
}

func escape(_ text: String) -> String {
    text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
}

// MARK: Packets

/// One packet inside a lane's repeating pattern. `head` is its leading edge.
struct Packet { let head: Double; let length: Double }

/// Places packets along one pattern period. Frequency follows the traffic rate on a log
/// scale; exponential gaps give the uneven, bursty spacing of real traffic.
func makePackets(rate: Double, period: Double, options: Options, random: inout Random) -> [Packet] {
    guard rate > 0, options.density > 0 else { return [] }
    let perThousandPixels = options.density * (0.6 + 1.5 * log10(1 + rate / 1000))
    var count = max(1, Int((perThousandPixels * period / 1000).rounded()))
    let lengths = (0..<count).map { _ in 52 * options.packetSize * random.range(0.45, 1.7) }
    let minimumGap = 18 * options.packetSize
    while count > 1, lengths.prefix(count).reduce(0, +) + Double(count) * minimumGap > period { count -= 1 }
    let free = max(0, period - lengths.prefix(count).reduce(0, +) - Double(count) * minimumGap)
    let weights = (0..<count).map { _ in -log(1 - 0.995 * random.next()) }
    let total = weights.reduce(0, +)
    var cursor = 0.0
    return (0..<count).map { index in
        cursor += minimumGap + free * weights[index] / total + lengths[index]
        return Packet(head: cursor, length: lengths[index])
    }
}

/// Dash pattern for one trail layer: the front `fraction` of every packet, aligned on its head.
/// The pattern opens with a zero-length dash so every layer shares offset 0.
func dashArray(_ packets: [Packet], period: Double, fraction: Double, minimum: Double = 0) -> String {
    var values = [0.0]
    var end = 0.0
    for packet in packets {
        let length = min(packet.length, max(minimum, packet.length * fraction))
        values += [packet.head - length - end, length]
        end = packet.head
    }
    values.append(max(0, period - end))
    return values.map { n($0) }.joined(separator: " ")
}

// MARK: Rendering

struct Lane {
    let id: String
    let path: String               // Cable path id, in the direction of travel.
    let period: Double
    let duration: Double
    let delay: Double
    let packets: [Packet]
}

func render(_ options: Options, links: [Link]) -> String {
    var random = Random(state: options.seed)
    let width = options.width, height = options.height, middle = height / 2
    let packetColor = RGB(hex: options.color)
    let cable = options.cableColor.map { RGB(hex: $0) } ?? packetColor.mix(black, 0.76)
    let background = RGB(hex: options.background)
    let palette = (
        trail: packetColor.hex,
        core: packetColor.mix(white, 0.38).hex,
        head: packetColor.mix(white, 0.9).hex,
        sheen: cable.mix(white, 0.14).hex,
        plate: background.mix(white, 0.035).hex,
        edge: cable.mix(background, 0.35).hex,
        label: packetColor.mix(white, 0.55).hex,
        eyebrow: packetColor.mix(white, 0.2).hex
    )

    // Patch panel sits after the title; cables fan out from it to the right edge.
    let spacing = min(30, (height - 96) / Double(links.count))
    let panelX = max(430, width * 0.36), plateWidth = 128.0
    let plateHeight = Double(links.count) * spacing + 28
    let cableStart = panelX + plateWidth + 4
    let fan = min(1.75, (height - 24) / max(1, Double(links.count - 1) * spacing))

    var defs = [String](), cables = [String](), halos = [String](), lanes = [String]()
    var styles = [String](), panel = [String]()
    var laneCount = 0

    panel.append(#"<rect x="\#(n(panelX))" y="\#(n(middle - plateHeight / 2))" width="\#(n(plateWidth))" height="\#(n(plateHeight))" rx="6" fill="\#(palette.plate)" stroke="\#(palette.edge)"/>"#)
    for y in [middle - plateHeight / 2 + 8, middle + plateHeight / 2 - 8] {
        for x in [panelX + 8, panelX + plateWidth - 8] {
            panel.append(#"<circle cx="\#(n(x))" cy="\#(n(y))" r="2.2" fill="\#(background.hex)" stroke="\#(palette.edge)"/>"#)
        }
    }

    for (index, link) in links.enumerated() {
        let y = middle + (Double(index) - Double(links.count - 1) / 2) * spacing
        let end = middle + (y - middle) * fan + random.range(-8, 8)
        let curve = Cubic(p0: Point(x: cableStart, y: y),
                          p1: Point(x: cableStart + random.range(150, 240), y: y),
                          p2: Point(x: width - random.range(170, 320), y: end),
                          p3: Point(x: width + 40, y: end))
        let length = curve.length
        defs.append(#"<path id="c\#(index)" d="\#(curve.d)"/>"#)
        defs.append(#"<path id="c\#(index)r" d="\#(curve.reversed.d)"/>"#)

        let idle = link.rx <= 0 && link.tx <= 0
        let cableRef = "#c\(index)"
        cables.append(#"<g opacity="\#(idle ? "0.5" : "1")"><use href="\#(cableRef)" stroke="\#(cable.hex)" stroke-width="3.2"/><use href="\#(cableRef)" stroke="\#(palette.sheen)" stroke-width="0.9" stroke-opacity="0.55"/></g>"#)

        // Jack, plug, and port label on the patch panel.
        panel.append(#"<text x="\#(n(panelX + 14))" y="\#(n(y + 3.8))" class="port"\#(idle ? #" opacity="0.45""# : "")>\#(escape(link.label))</text>"#)
        panel.append(#"<rect x="\#(n(panelX + 84))" y="\#(n(y - 7))" width="24" height="14" rx="2" fill="\#(background.hex)" stroke="\#(palette.edge)"/>"#)
        panel.append(#"<rect x="\#(n(panelX + 92))" y="\#(n(y - 4.5))" width="\#(n(cableStart - panelX - 90))" height="9" rx="2" fill="\#(cable.mix(white, 0.06).hex)" stroke="\#(palette.edge)" stroke-width="0.8"/>"#)

        var directions = [(String, Double)]()
        if options.direction != .inbound { directions.append(("c\(index)", link.tx)) }
        if options.direction != .outbound { directions.append(("c\(index)r", link.rx)) }
        for (path, rate) in directions where rate > 0 {
            let period = (length + 120) * random.range(1.25, 2.1)
            let packets = makePackets(rate: rate, period: period, options: options, random: &random)
            if packets.isEmpty { continue }
            let pathRef = "#" + path
            let duration = period / (options.speed * random.range(0.8, 1.25))
            let lane = Lane(id: "l\(laneCount)", path: path, period: period, duration: duration,
                            delay: -random.range(0, duration), packets: packets)
            laneCount += 1
            styles.append("@keyframes \(lane.id){to{stroke-dashoffset:-\(n(period))px}}.\(lane.id){animation-name:\(lane.id);animation-duration:\(n(duration, 2))s;animation-delay:\(n(lane.delay, 2))s}")

            if options.glow > 0 {
                halos.append(#"<use href="\#(pathRef)" class="lane \#(lane.id)" stroke-dasharray="\#(dashArray(packets, period: period, fraction: 0.6))"/>"#)
            }
            // Stacked trail layers, each shorter and brighter, read as a fading gradient.
            var layers = [String]()
            for (fraction, opacity) in [(1.0, 0.26), (0.75, 0.3), (0.52, 0.34), (0.32, 0.4)] {
                layers.append(#"<use href="\#(pathRef)" stroke="\#(palette.trail)" stroke-width="1.8" stroke-opacity="\#(opacity)" stroke-dasharray="\#(dashArray(packets, period: period, fraction: fraction))"/>"#)
            }
            layers.append(#"<use href="\#(pathRef)" stroke="\#(palette.core)" stroke-width="2.1" stroke-opacity="0.9" stroke-dasharray="\#(dashArray(packets, period: period, fraction: 0.14, minimum: 6))"/>"#)
            layers.append(#"<use href="\#(pathRef)" stroke="\#(palette.head)" stroke-width="2.3" stroke-dasharray="\#(dashArray(packets, period: period, fraction: 0, minimum: 4))"/>"#)
            lanes.append(#"<g class="lane \#(lane.id)">\#(layers.joined())</g>"#)
        }
    }

    let subtitle = options.subtitle.split(separator: "|").enumerated().map { index, line in
        #"<text x="56" y="\#(n(middle + 50 + Double(index) * 27))" class="subtitle">\#(escape(String(line)))</text>"#
    }.joined()
    let glowFilter = options.glow > 0 ? #"<filter id="glow" filterUnits="userSpaceOnUse" x="0" y="0" width="\#(n(width))" height="\#(n(height))"><feGaussianBlur stdDeviation="\#(n(2 + 2.5 * options.glow))"/></filter>"# : ""
    let haloGroup = halos.isEmpty ? "" : #"<g filter="url(#glow)" stroke="\#(palette.trail)" stroke-width="\#(n(4 + 3 * options.glow))" stroke-opacity="\#(n(min(0.9, 0.42 * options.glow), 2))">\#(halos.joined())</g>"#
    let description = "Data packets travel in both directions through network cables plugged into local ports. Busy ports carry more packets; idle ports stay dark."

    return """
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 \(n(width)) \(n(height))" width="\(n(width))" height="\(n(height))" role="img" aria-labelledby="title desc">
    <title id="title">\(escape(options.title))</title>
    <desc id="desc">\(description)</desc>
    <style>
    text{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",Helvetica,Arial,sans-serif}
    .eyebrow{font-size:12px;font-weight:600;letter-spacing:3px;fill:\(palette.eyebrow)}
    .title{font-size:92px;font-weight:700;letter-spacing:-3px;fill:#f6eeee}
    .subtitle{font-size:19px;fill:\(palette.label);fill-opacity:.78}
    .port{font:500 11px ui-monospace,"SF Mono",Menlo,Consolas,monospace;fill:\(palette.label);fill-opacity:.75}
    use{fill:none}
    .lane{animation-timing-function:linear;animation-iteration-count:infinite}
    \(styles.joined(separator: "\n"))
    @media (prefers-reduced-motion:reduce){.lane{animation:none}}
    </style>
    <defs>
    <radialGradient id="ambient" cx="0.74" cy="0.5" r="0.62"><stop offset="0" stop-color="\(packetColor.hex)" stop-opacity="0.07"/><stop offset="1" stop-color="\(packetColor.hex)" stop-opacity="0"/></radialGradient>
    <clipPath id="frame"><rect width="\(n(width))" height="\(n(height))" rx="16"/></clipPath>
    \(glowFilter)
    \(defs.joined(separator: "\n"))
    </defs>
    <g clip-path="url(#frame)">
    <rect width="\(n(width))" height="\(n(height))" fill="\(background.hex)"/>
    <rect width="\(n(width))" height="\(n(height))" fill="url(#ambient)"/>
    <g>\(cables.joined())</g>
    \(haloGroup)
    <g stroke-linecap="butt">\(lanes.joined())</g>
    <g>\(panel.joined())</g>
    <text x="56" y="\(n(middle - 66))" class="eyebrow">\(escape(options.eyebrow))</text>
    <text x="50" y="\(n(middle + 14))" class="title">\(escape(options.title))</text>
    \(subtitle)
    </g>
    </svg>

    """
}

let options = parseOptions(Array(CommandLine.arguments.dropFirst()))
let links = options.traffic.map(readTraffic) ?? sampleTraffic
let svg = render(options, links: links)
if let output = options.output {
    do { try svg.write(toFile: output, atomically: true, encoding: .utf8) } catch { fail("cannot write \(output): \(error.localizedDescription)") }
} else {
    print(svg, terminator: "")
}
