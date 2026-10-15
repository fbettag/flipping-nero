import ActivityKit
import AppIntents
import Foundation

// Compiled into the app and the widget extension. The widget only renders; the intents'
// work runs in the app process, which is where the run and its session live.

/// Live Activity for an active run: phase, host count, findings and the pending
/// approval with Allow/Deny on the Lock Screen.
struct RunActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        /// discover → ports → checks → report
        var phase: String
        var detail: String
        var hostsSeen: Int
        var findings: Int
        /// 0...1 while a sweep is running, nil otherwise.
        var progress: Double?
        var approvalPending: Bool
        var approvalSummary: String
        var isFinished: Bool
    }

    var runTitle: String
    var startedAt: Date
}

/// Stops the run. Shown as the Live Activity's button and available in Siri and Shortcuts.
/// Stopping is always free; no confirmation.
struct StopRunIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Stop Run"
    static let description = IntentDescription("Stops the active run, saves a partial report and disarms the scope.")
    static let openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        #if WIDGET_EXTENSION
        return .result(dialog: "")
        #else
        let stopped = await AppModel.shared.stopRun()
        return .result(dialog: stopped ? "Run stopped, partial report saved." : "No run is active.")
        #endif
    }
}

/// Lock-Screen Allow for a pending run step. Requires device authentication (Face ID,
/// Touch ID or passcode), per the approval policy.
struct ApproveStepIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Allow"
    static let description = IntentDescription("Approves the pending step of the active run.")
    static let openAppWhenRun = false
    static var authenticationPolicy: IntentAuthenticationPolicy { .requiresLocalDeviceAuthentication }

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        #if WIDGET_EXTENSION
        return .result(dialog: "")
        #else
        let resolved = await AppModel.shared.resolveLiveApproval(true)
        return .result(dialog: resolved ? "Approved, run continues." : "No pending step.")
        #endif
    }
}

/// Lock-Screen Deny for a pending run step. Denying needs no authentication.
struct DenyStepIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Deny"
    static let description = IntentDescription("Denies the pending step; the run continues with the next one.")
    static let openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        #if WIDGET_EXTENSION
        return .result(dialog: "")
        #else
        let resolved = await AppModel.shared.resolveLiveApproval(false)
        return .result(dialog: resolved ? "Denied, run continues." : "No pending step.")
        #endif
    }
}
