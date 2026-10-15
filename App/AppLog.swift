import Foundation
import os

/// Unified logging. Debug builds also print, so `devicectl device process launch --console`
/// shows the messages while testing against a real network.
enum AppLog {
    private static let logger = Logger(subsystem: Bundle.main.bundleIdentifier ?? "FlippingNero", category: "app")

    static func info(_ message: String) {
        logger.info("\(message, privacy: .public)")
        #if DEBUG
        print("[Nero] \(message)")
        #endif
    }

    static func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
        #if DEBUG
        print("[Nero] error: \(message)")
        #endif
    }

    /// Chatty per-event tracing; debug builds only print, release builds stay quiet.
    static func debug(_ message: String) {
        #if DEBUG
        logger.debug("\(message, privacy: .public)")
        print("[Nero] \(message)")
        #endif
    }
}
