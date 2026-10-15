// Generates the asset catalog bitmaps: the app icon and the Logo image set.
// Icon per the readme: flat black cat, raised middle finger, one color.
// Run: swift scripts/make-assets.swift
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let assets = root.appendingPathComponent("App/Assets.xcassets")

func writePNG(_ image: CGImage, to url: URL) {
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, image, nil)
    CGImageDestinationFinalize(destination)
}

func context(_ size: CGFloat) -> CGContext {
    CGContext(data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
              space: CGColorSpace(name: CGColorSpace.sRGB)!,
              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
}

let background = CGColor(srgbRed: 0.03, green: 0.03, blue: 0.035, alpha: 1)
let accent = CGColor(srgbRed: 1.0, green: 0.16, blue: 0.18, alpha: 1)

/// Draws the mark into a square canvas of the given size (in points, scaled).
func drawMark(size: CGFloat) -> CGImage {
    let c = context(size)
    let s = size / 1024.0 // design grid
    c.setFillColor(background)
    c.fill(CGRect(x: 0, y: 0, width: size, height: size))

    // Cat head: round head with two triangular ears.
    c.setFillColor(accent)
    let headCenter = CGPoint(x: 512 * s, y: 620 * s)
    let headRadius = 180 * s
    c.addArc(center: headCenter, radius: headRadius, startAngle: .pi * 0.02, endAngle: .pi * 0.98, clockwise: false)
    // Left ear
    c.addLines(between: [
        CGPoint(x: 352 * s, y: 700 * s),
        CGPoint(x: 322 * s, y: 880 * s),
        CGPoint(x: 470 * s, y: 776 * s),
    ])
    // Right ear
    c.addLines(between: [
        CGPoint(x: 672 * s, y: 700 * s),
        CGPoint(x: 702 * s, y: 880 * s),
        CGPoint(x: 554 * s, y: 776 * s),
    ])
    c.closePath()
    c.fillPath()

    // Raised middle finger in front of the head: fist plus one extended finger.
    // A background-colored halo separates the hand from the head where they cross.
    let fist = CGRect(x: 396 * s, y: 110 * s, width: 232 * s, height: 210 * s)
    let finger = CGRect(x: 480 * s, y: 250 * s, width: 64 * s, height: 340 * s)
    let halo: CGFloat = 16 * s

    c.setFillColor(background)
    c.addPath(CGPath(roundedRect: fist.insetBy(dx: -halo, dy: -halo),
                     cornerWidth: 68 * s, cornerHeight: 68 * s, transform: nil))
    c.fillPath()
    c.addPath(CGPath(roundedRect: finger.insetBy(dx: -halo, dy: -halo),
                     cornerWidth: 48 * s, cornerHeight: 48 * s, transform: nil))
    c.fillPath()

    c.setFillColor(accent)
    c.addPath(CGPath(roundedRect: fist, cornerWidth: 54 * s, cornerHeight: 54 * s, transform: nil))
    c.fillPath()
    c.addPath(CGPath(roundedRect: finger, cornerWidth: 32 * s, cornerHeight: 32 * s, transform: nil))
    c.fillPath()

    // Two folded knuckle hints on the fist, cut out of the silhouette.
    c.setBlendMode(.clear)
    for x in [452.0, 556.0] {
        let notch = CGRect(x: x * s, y: 236 * s, width: 16 * s, height: 44 * s)
        c.addPath(CGPath(roundedRect: notch, cornerWidth: 8 * s, cornerHeight: 8 * s, transform: nil))
        c.fillPath()
    }
    c.setBlendMode(.normal)
    return c.makeImage()!
}

// App icon: single 1024 size, modern asset catalogs scale it.
let icon = drawMark(size: 1024)
let iconSet = assets.appendingPathComponent("AppIcon.appiconset")
writePNG(icon, to: iconSet.appendingPathComponent("icon-1024.png"))
try? """
{
  "images" : [
    {
      "filename" : "icon-1024.png",
      "idiom" : "universal",
      "platform" : "ios",
      "size" : "1024x1024"
    }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
""".write(to: iconSet.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)

// Logo image set for the brand header and the widget.
let logo = drawMark(size: 256)
let logoSet = assets.appendingPathComponent("Logo.imageset")
writePNG(logo, to: logoSet.appendingPathComponent("logo.png"))
try? """
{
  "images" : [
    { "idiom" : "universal", "scale" : "1x" },
    { "filename" : "logo.png", "idiom" : "universal", "scale" : "2x" },
    { "idiom" : "universal", "scale" : "3x" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
""".write(to: logoSet.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)

// Launch background color.
try? """
{
  "colors" : [
    {
      "color" : {
        "color-space" : "srgb",
        "components" : { "alpha" : "1.000", "blue" : "0.035", "green" : "0.030", "red" : "0.030" }
      },
      "idiom" : "universal"
    }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
""".write(to: assets.appendingPathComponent("LaunchBackground.colorset/Contents.json"), atomically: true, encoding: .utf8)

try? """
{
  "info" : { "author" : "xcode", "version" : 1 }
}
""".write(to: assets.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)

print("assets written to \(assets.path)")
