import Foundation

/// Strips control characters and fence-like markers from text that may have been
/// written by third parties. AgentKit's `Untrusted` builds its fencing on top of this.
public enum TextSanitizer {
    /// Removes control characters (except \n and \t) and truncates.
    public static func clean(_ text: String, maxLength: Int = 8_000) -> String {
        var out = ""
        out.reserveCapacity(min(text.count, maxLength))
        for scalar in text.unicodeScalars {
            if scalar == "\n" || scalar == "\t" { out.unicodeScalars.append(scalar) }
            else if scalar.value < 0x20 || scalar.value == 0x7F { continue }
            else { out.unicodeScalars.append(scalar) }
            if out.count >= maxLength { break }
        }
        if text.count > maxLength { out += "\n[truncated]" }
        return out
    }

    /// One-line, length-capped form for names, banners and notes.
    public static func sanitizeName(_ name: String) -> String {
        clean(name.replacingOccurrences(of: "\n", with: " "), maxLength: 120)
    }
}
