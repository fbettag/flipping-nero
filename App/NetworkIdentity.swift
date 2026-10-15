import CoreLocation
import Foundation
import NetworkExtension
import NeroKit

/// The run title and scope source: the SSID of the current Wi-Fi (needs the Wi-Fi info
/// access plus location permission) and the current interface subnet.
@MainActor
enum NetworkIdentity {
    /// NEHotspotNetwork.fetchCurrent answers only with the entitlement, the location
    /// permission and a currently joined network; every failure falls back.
    static func ssid() async -> String? {
        let manager = CLLocationManager()
        let status = manager.authorizationStatus
        if status == .notDetermined {
            manager.requestWhenInUseAuthorization()
            return nil // This run shows the fallback; the next one gets the SSID after consent.
        }
        guard status == .authorizedWhenInUse || status == .authorizedAlways else { return nil }
        return await withCheckedContinuation { cont in
            NEHotspotNetwork.fetchCurrent { network in
                cont.resume(returning: network?.ssid)
            }
        }
    }

    /// The title a run gets: the SSID, otherwise a timestamped LAN name.
    static func runTitle(now: Date = Date()) async -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        if let ssid = await ssid(), !ssid.isEmpty {
            return TextSanitizer.sanitizeName(ssid)
        }
        return "LAN \(formatter.string(from: now))"
    }

    /// The scope source: the primary interface's subnet.
    static func localScope(startedAt: Date) -> IPv4CIDR? {
        guard let primary = NetworkContext.primary() else { return nil }
        return primary.cidr
    }

    /// One line about the network the phone is on, for the Run tab.
    static func contextSummary() -> String {
        NetworkContext.summary()
    }
}
