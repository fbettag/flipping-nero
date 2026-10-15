import Foundation
import NeroKit

/// What the operator grants when engagement is armed. The agent can ask for these,
/// but only the human arm dialog (or an approved `set_engagement` call) applies them.
public struct EngagementProfile: Sendable, Equatable, Codable {
    public var capabilities: Capabilities
    /// The operator's scope note, shown on the banner and injected into the system prompt.
    public var note: String

    public init(capabilities: Capabilities = Capabilities(), note: String = "") {
        self.capabilities = capabilities
        self.note = String(TextSanitizer.sanitizeName(note).prefix(200))
    }

    /// Short machine-readable summary for settings, audit and prompts.
    public var summary: String { capabilities.summary }
}

/// Session-only arming state. Never persisted: a restart always returns to disarmed,
/// and disconnect, expiry or app kill disarm the run.
public struct EngagementState: Sendable, Equatable, Codable {
    public var active: Bool
    public var profile: EngagementProfile
    public var startedAt: Date?

    public init(active: Bool = false, profile: EngagementProfile = EngagementProfile(), startedAt: Date? = nil) {
        self.active = active
        self.profile = profile
        self.startedAt = startedAt
    }

    public static let inactive = EngagementState()

    public func armed(_ capability: KeyPath<Capabilities, Bool>) -> Bool {
        active && profile.capabilities[keyPath: capability]
    }
}
