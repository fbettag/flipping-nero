import SwiftUI

enum Theme {
    static let accent = Color(red: 1.0, green: 0.16, blue: 0.18)
    static let background = Color(red: 0.03, green: 0.03, blue: 0.035)
    static let card = Color(white: 0.10)
    static let stroke = Color.white.opacity(0.09)
    static let ok = Color(red: 0.30, green: 0.85, blue: 0.45)
    static let warn = Color(red: 1.0, green: 0.72, blue: 0.11)
    static let danger = Color(red: 1.0, green: 0.32, blue: 0.30)

    static var glow: some View {
        LinearGradient(colors: [accent.opacity(0.12), .clear], startPoint: .top, endPoint: .init(x: 0.5, y: 0.45))
            .ignoresSafeArea()
    }
}
