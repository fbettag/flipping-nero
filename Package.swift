// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FlippingNero",
    defaultLocalization: "en",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "NeroKit", targets: ["NeroKit"]),
        .library(name: "AgentKit", targets: ["AgentKit"]),
    ],
    targets: [
        .target(name: "NeroKit"),
        .target(name: "AgentKit", dependencies: ["NeroKit"]),
        .testTarget(name: "NeroKitTests", dependencies: ["NeroKit"]),
        .testTarget(name: "AgentKitTests", dependencies: ["AgentKit"]),
    ],
    swiftLanguageModes: [.v5]
)
