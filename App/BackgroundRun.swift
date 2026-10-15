import BackgroundTasks
import Foundation
import UIKit

/// iOS 26 continued processing: the run keeps going when the phone is locked, with the
/// Live Activity as its face. Progress is reported on every tool event, because a task
/// that looks stalled gets expired. The expiration handler saves a partial report.
///
/// Identifier scheme: Info.plist permits `<bundle>.run.*`; every run registers its
/// launch handler under its own concrete `<bundle>.run.<uuid>` right before submitting.
/// The scheduler looks handlers up by the concrete identifier, and continued-processing
/// registrations are explicitly exempt from the register-before-launch rule.
@MainActor
final class BackgroundRunController {
    static var wildcard: String {
        (Bundle.main.bundleIdentifier ?? "FlippingNero") + ".run.*"
    }

    /// The base class is as old as the scheduler; the continued-processing API is iOS 26.
    private var task: BGTask?
    private var lastIdentifier: String?

    @available(iOS 26.0, *)
    private func handle(_ task: BGContinuedProcessingTask) {
        self.task = task
        task.progress.totalUnitCount = 100
        task.expirationHandler = {
            Task { @MainActor in AppModel.shared.pauseForExpiration() }
        }
        AppLog.info("background run task started")
    }

    /// Registers the launch handler for one concrete run identifier and submits it.
    /// Submitted only from the Run tap, as the platform requires.
    func submit(title: String) async {
        guard #available(iOS 26.0, *) else { return }
        let identifier = Self.wildcard.droppingWildcardAppending(UUID().uuidString)
        let registered = BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) {
            [weak self] raw in
            guard let continued = raw as? BGContinuedProcessingTask else { return }
            Task { @MainActor in self?.handle(continued) }
        }
        guard registered else {
            AppLog.error("could not register a launch handler for \(identifier)")
            return
        }
        lastIdentifier = identifier
        let request = BGContinuedProcessingTaskRequest(
            identifier: identifier,
            title: title,
            subtitle: "Network recon run")
        request.strategy = .queue
        do {
            if #available(iOS 27.0, *) {
                try await BGTaskScheduler.shared.submitTaskRequest(request)
            } else {
                try await BGTaskScheduler.shared.submit(request)
            }
        } catch {
            // Without the background task the run simply continues in the foreground
            // under the keep-awake setting.
            AppLog.error("continued processing submit failed: \(error)")
        }
    }

    func updateProgress(fraction: Double?, phase: String) {
        guard #available(iOS 26.0, *) else { return }
        guard let continued = task as? BGContinuedProcessingTask else { return }
        if let fraction {
            continued.progress.completedUnitCount = Int64((fraction * 100).rounded())
        }
        continued.updateTitle(phase, subtitle: "")
    }

    func finish(success: Bool) {
        guard #available(iOS 26.0, *) else { return }
        task?.setTaskCompleted(success: success)
        task = nil
        // Drop a possibly queued request so the next run starts clean.
        if let identifier = lastIdentifier {
            try? BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: identifier)
            lastIdentifier = nil
        }
    }
}

private extension String {
    /// ".run.*" + "uuid" -> ".run.uuid"
    func droppingWildcardAppending(_ suffix: String) -> String {
        hasSuffix(".*") ? String(dropLast(2)) + "." + suffix : self + "." + suffix
    }
}
