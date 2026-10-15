import Foundation
import NeroKit

/// Thread-safe snapshots for the executor, which runs off the main actor.
/// The app keeps the truth on the main actor and mirrors it into these boxes.
public final class PolicyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var yolo = false
    private var asksAfterUntrusted = true
    private var engagement = EngagementState.inactive
    public func set(yolo: Bool, asksAfterUntrusted: Bool, engagement: EngagementState) {
        lock.withLock {
            self.yolo = yolo
            self.asksAfterUntrusted = asksAfterUntrusted
            self.engagement = engagement
        }
    }
    public var snapshot: (yolo: Bool, asksAfterUntrusted: Bool, engagement: EngagementState) {
        lock.withLock { (yolo, asksAfterUntrusted, engagement) }
    }
    public init() {}
}

public final class ScopeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var policy: ScopePolicy?
    public func set(_ policy: ScopePolicy?) { lock.withLock { self.policy = policy } }
    public var current: ScopePolicy? { lock.withLock { policy } }
    public init() {}
}

public final class ForegroundBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value = true
    public func set(_ value: Bool) { lock.withLock { self.value = value } }
    public var isForeground: Bool { lock.withLock { value } }
    public init() {}
}
