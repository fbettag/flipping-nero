import Foundation
import NeroKit

public enum RiskLevel: Int, Sendable, Comparable, Codable {
    case low = 0, medium, high, blocked
    public static func < (a: RiskLevel, b: RiskLevel) -> Bool { a.rawValue < b.rawValue }
}

public struct RiskAssessment: Sendable, Equatable {
    public var level: RiskLevel
    public var reasons: [String]
}

/// Deterministic, model-independent risk classification. The model never supplies
/// or influences the risk level; it comes out of the parsed, validated call.
public enum RiskAssessor {
    public static func assess(_ invocation: ToolInvocation) -> RiskAssessment {
        switch invocation {
        case .getNetworkContext:
            return .init(level: .low, reasons: ["reads the phone's own network context, changes nothing"])
        case .browseBonjour:
            return .init(level: .low, reasons: ["browses service announcements, contacts no target directly"])
        case .dnsLookup:
            return .init(level: .low, reasons: ["queries the system resolver, contacts no target"])
        case .discoverHosts(let cidr):
            return .init(level: .medium, reasons: ["sweeps \(cidr.string) for live hosts"])
        case .scanPorts(let host, let ports):
            return .init(level: .medium, reasons: ["connect-scans \(host.string) on \(ports.count) ports"])
        case .grabBanner(let host, let port):
            return .init(level: .medium, reasons: ["connects to \(host.string):\(port) and reads the banner"])
        case .httpRequest(let method, _, _, _):
            if method == "POST" || method == "PUT" {
                return .init(level: .high, reasons: ["\(method) can change state on the target"])
            }
            return .init(level: .medium, reasons: ["\(method) reads from the target"])
        case .recordFinding:
            return .init(level: .low, reasons: ["writes a finding into the local report"])
        case .getFindings, .getAuditLog, .getAppSettings:
            return .init(level: .low, reasons: ["read-only"])
        case .exportReport:
            return .init(level: .low, reasons: ["writes the report into the app container; nothing leaves the phone"])
        case .setScope:
            return .init(level: .medium, reasons: ["changes what this run may touch"])
        case .setYoloMode(let on):
            return on
                ? .init(level: .high, reasons: ["scans and checks would then run without asking you"])
                : .init(level: .low, reasons: ["makes the agent ask again"])
        case .setAutoApproveMedium(let on):
            return on
                ? .init(level: .high, reasons: ["medium-risk actions would no longer ask you"])
                : .init(level: .low, reasons: ["makes the agent ask again"])
        case .setYoloAsksAfterUntrusted(let on):
            return on
                ? .init(level: .low, reasons: ["keeps asking after the agent read network content"])
                : .init(level: .high, reasons: ["removes the protection against instructions planted in network content"])
        case .listModels:
            return .init(level: .low, reasons: ["reads the provider's model catalog, changes nothing"])
        case .testConnection:
            return .init(level: .medium, reasons: ["sends a paid test message to your model provider"])
        case .setEngagement(let enabled, let profile):
            if !enabled {
                return .init(level: .low, reasons: ["ends engagement mode; the agent asks again"])
            }
            var reasons = ["the agent runs actions without asking for the rest of the session"]
            if profile.capabilities.exploit { reasons.append("exploit modules and credential spray become available") }
            if profile.capabilities.cloudReadonly { reasons.append("an explicit link-local metadata target becomes reachable") }
            if profile.capabilities.pivot { reasons.append("the Field Node capability is reserved") }
            return .init(level: .high, reasons: reasons)
        case .exploitCheck(let module, let host, let port):
            return .init(level: .high, reasons: ["sends exploit probes for '\(module)' to \(host.string)\(port.map { ":\($0)" } ?? "")"])
        case .exploitRun(let module, let host, let port):
            return .init(level: .high, reasons: ["runs the exploit module '\(module)' against \(host.string)\(port.map { ":\($0)" } ?? "")"])
        case .authSpray(let service, let host, let port, _):
            return .init(level: .high, reasons: ["tries the fixed credential bundle against \(service) on \(host.string)\(port.map { ":\($0)" } ?? "")"])
        }
    }
}
