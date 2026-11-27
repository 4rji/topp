// Render the README's port panel and packet lanes at each macOS icon size.
import CoreGraphics
import CoreText
import Foundation
import ImageIO

func color(_ rgb: Int) -> CGColor {
    CGColor(srgbRed: CGFloat(rgb >> 16) / 255,
            green: CGFloat((rgb >> 8) & 255) / 255,
            blue: CGFloat(rgb & 255) / 255, alpha: 1)
}

func rounded(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ radius: CGFloat) -> CGPath {
    CGPath(roundedRect: CGRect(x: x, y: y, width: w, height: h), cornerWidth: radius, cornerHeight: radius, transform: nil)
}

func render(pixels: Int, to url: URL) throws {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    guard let ctx = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0,
                              space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
        throw CocoaError(.fileWriteUnknown)
    }
    ctx.translateBy(x: 0, y: CGFloat(pixels))
    ctx.scaleBy(x: CGFloat(pixels) / 256, y: -CGFloat(pixels) / 256)
    func fill(_ path: CGPath, _ rgb: Int) {
        ctx.addPath(path)
        ctx.setFillColor(color(rgb))
        ctx.fillPath()
    }
    func stroke(_ path: CGPath, _ rgb: Int, _ width: CGFloat) {
        ctx.addPath(path)
        ctx.setStrokeColor(color(rgb))
        ctx.setLineWidth(width)
        ctx.strokePath()
    }

    let tile = rounded(14, 14, 228, 228, 51)
    ctx.addPath(tile)
    ctx.clip()
    let gradient = CGGradient(colorsSpace: space, colors: [color(0x0a0506), color(0x351019)] as CFArray,
                              locations: [0, 1])!
    ctx.drawLinearGradient(gradient, start: CGPoint(x: 94, y: 16), end: CGPoint(x: 224, y: 248), options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    stroke(tile, 0x45232c, 2)

    ctx.saveGState()
    ctx.translateBy(x: 36, y: 100)
    ctx.scaleBy(x: 1, y: -1)
    let attributes = [kCTFontAttributeName: CTFontCreateWithName("HelveticaNeue-Bold" as CFString, 69, nil),
                      kCTForegroundColorAttributeName: color(0xf6eeee), kCTKernAttributeName: -2.6] as [CFString: Any]
    let wordmark = CFAttributedStringCreate(nil, "topp" as CFString, attributes as CFDictionary)!
    CTLineDraw(CTLineCreateWithAttributedString(wordmark), ctx)
    ctx.restoreGState()

    let panel = rounded(37, 126, 62, 83, 9)
    fill(panel, 0x28171c)
    stroke(panel, 0x65313e, 1.5)
    ctx.setLineCap(.round)
    for (index, endY) in [105, 158, 217].enumerated() {
        let y = CGFloat(144 + index * 24)
        let lane = CGMutablePath()
        lane.move(to: CGPoint(x: 94, y: y))
        lane.addCurve(to: CGPoint(x: 255, y: endY), control1: CGPoint(x: 148, y: y),
                      control2: CGPoint(x: 188, y: endY))
        stroke(lane, 0x733048, 5)
        stroke(lane, 0x411523, 2)
        let packet = lane.copy(dashingWithPhase: CGFloat([2, 52, 27][index]), lengths: [23, 66])
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: CGFloat(pixels) * 0.024, color: color(0xe4002b))
        stroke(packet, 0xe93355, 5.5)
        ctx.restoreGState()
        stroke(packet, 0xff9aad, 1.8)
        fill(rounded(47, y - 2, 7, 4, 2), 0xf35d7c)
        fill(rounded(61, y - 7, 33, 14, 3), 0x0a0506)
        fill(rounded(69, y - 4, 35, 8, 2), 0x864051)
        fill(rounded(71, y - 3, 29, 2, 1), 0xba697c)
    }
    guard let image = ctx.makeImage(), let dest = CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil) else {
        throw CocoaError(.fileWriteUnknown)
    }
    CGImageDestinationAddImage(dest, image, nil)
    guard CGImageDestinationFinalize(dest) else { throw CocoaError(.fileWriteUnknown) }
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("Usage: swift app-icon.swift <output.iconset>\n".utf8))
    exit(2)
}
let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let suffix = scale == 1 ? "" : "@2x"
        try render(pixels: size * scale, to: directory.appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
    }
}
