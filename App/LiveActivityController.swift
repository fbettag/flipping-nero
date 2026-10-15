import ActivityKit
import Foundation

/// Shows the active run on the Lock Screen and in the Dynamic Island: phase, hosts,
/// findings, and the pending approval with Allow/Deny.
@MainActor
final class LiveActivityController {
    private typealias RunActivity = Activity<RunActivityAttributes>
    private var run: RunActivity?
    private var lastState: RunActivityAttributes.ContentState?

    /// Ends activities left over from a previous launch; nothing is running after a fresh start.
    func endStale() {
        for activity in RunActivity.activities {
            Task { await activity.end(nil, dismissalPolicy: .immediate) }
        }
    }

    func runStarted(title: String, detail: String) {
        end(run)
        run = nil
        lastState = nil
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        let attributes = RunActivityAttributes(runTitle: title, startedAt: .now)
        let state = RunActivityAttributes.ContentState(
            phase: "discover", detail: detail, hostsSeen: 0, findings: 0, progress: nil,
            approvalPending: false, approvalSummary: "", isFinished: false)
        do {
            run = try RunActivity.request(attributes: attributes, content: .init(state: state, staleDate: nil))
            lastState = state
        } catch {
            AppLog.error("live activity failed: \(error)")
        }
    }

    /// Progress updates at least every tool event; the system expires a continued
    /// processing task that looks stalled, so this is also the heartbeat.
    func runChanged(phase: String, detail: String, hosts: Int, findings: Int, progress: Double?,
                    approvalPending: Bool, approvalSummary: String, finished: Bool) {
        let state = RunActivityAttributes.ContentState(
            phase: phase, detail: detail, hostsSeen: hosts, findings: findings, progress: progress,
            approvalPending: approvalPending, approvalSummary: approvalSummary, isFinished: finished)
        guard state != lastState else { return }
        lastState = state
        guard let activity = run else { return }
        if finished {
            let current = activity
            run = nil
            Task {
                await current.end(.init(state: state, staleDate: nil), dismissalPolicy: .after(.now + 15 * 60))
            }
        } else {
            let current = activity
            Task { await current.update(.init(state: state, staleDate: nil)) }
        }
    }

    func approvalPending(summary: String) {
        guard let activity = run, let last = lastState else { return }
        var state = last
        state.approvalPending = true
        state.approvalSummary = summary
        state.progress = nil
        lastState = state
        let current = activity
        Task { await current.update(.init(state: state, staleDate: nil)) }
    }

    func approvalResolved() {
        guard let activity = run, let last = lastState else { return }
        var state = last
        state.approvalPending = false
        state.approvalSummary = ""
        lastState = state
        let current = activity
        Task { await current.update(.init(state: state, staleDate: nil)) }
    }

    func runEnded() {
        end(run)
        run = nil
        lastState = nil
    }

    private func end(_ activity: RunActivity?) {
        guard let activity else { return }
        Task { await activity.end(nil, dismissalPolicy: .immediate) }
    }
}
