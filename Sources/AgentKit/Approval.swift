import Foundation

public struct ApprovalSettings: Sendable, Equatable {
    /// Skip the prompt for medium-risk actions.
    public var autoApproveMedium = false
    /// Skip the prompt for high-risk actions too. Blocked actions stay blocked.
    public var yolo = false
    /// In YOLO mode, still ask when the action follows content the agent read from the network.
    public var yoloAsksAfterUntrusted = true
    /// Armed engagement. Pre-authorizes a capability set for the session.
    public var engagement = EngagementState.inactive

    public init(autoApproveMedium: Bool = false, yolo: Bool = false, yoloAsksAfterUntrusted: Bool = true,
                engagement: EngagementState = .inactive) {
        self.autoApproveMedium = autoApproveMedium
        self.yolo = yolo
        self.yoloAsksAfterUntrusted = yoloAsksAfterUntrusted
        self.engagement = engagement
    }
}

/// A loot item shown once in the approval sheet: id, kind and a short redacted preview.
/// Approving the request is what moves the item's full value into the vault.
public struct ApprovalLoot: Sendable, Equatable {
    public var id: String
    public var kind: String
    public var preview: String
    public init(id: String, kind: String, preview: String) {
        self.id = id
        self.kind = kind
        self.preview = preview
    }
}

public struct ApprovalRequest: Sendable, Identifiable, Equatable {
    public let id = UUID()
    public var tool: String
    public var summary: String
    public var risk: RiskLevel
    public var reasons: [String]
    public var diff: String?
    /// The action was requested after the model read network content in this turn.
    public var afterUntrustedContent: Bool
    /// The agent asks to loosen its own permissions; the UI presents this as a permission dialog.
    public var isPermissionChange: Bool
    /// Loot whose full value should be shown once in this approval, then kept in the store.
    public var lootPreviews: [ApprovalLoot] = []

    public init(tool: String, summary: String, risk: RiskLevel, reasons: [String],
                diff: String? = nil, afterUntrustedContent: Bool = false, isPermissionChange: Bool = false,
                lootPreviews: [ApprovalLoot] = []) {
        self.tool = tool
        self.summary = summary
        self.risk = risk
        self.reasons = reasons
        self.diff = diff
        self.afterUntrustedContent = afterUntrustedContent
        self.isPermissionChange = isPermissionChange
        self.lootPreviews = lootPreviews
    }
}

public protocol ApprovalGate: Sendable {
    func decide(_ request: ApprovalRequest) async -> Bool
}

public enum ApprovalPolicy {
    public static func requiresApproval(_ assessment: RiskAssessment, settings: ApprovalSettings, tainted: Bool) -> Bool {
        requiresApproval(assessment.level, settings: settings, tainted: tainted)
    }

    public static func requiresApproval(_ level: RiskLevel, settings: ApprovalSettings, tainted: Bool) -> Bool {
        // Armed engagement: the operator pre-approved this session's actions up front.
        // Blocked levels never pass, and capability-gated tools are checked separately by the executor.
        if level != .blocked, settings.engagement.active, settings.engagement.profile.capabilities.autoApprovals {
            return false
        }
        switch level {
        case .low: return false
        case .blocked: return true
        case .medium, .high:
            if settings.yolo { return tainted && settings.yoloAsksAfterUntrusted }
            return level == .high || !settings.autoApproveMedium || tainted
        }
    }
}
