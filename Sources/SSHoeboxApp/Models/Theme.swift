import SwiftUI

struct AppTheme: Identifiable, Equatable {
    let id: String
    let name: String
    let background: Color
    let surface: Color
    let textPrimary: Color
    let textSecondary: Color
    let accent: Color
    let border: Color
    let success: Color
    let error: Color
    let colorScheme: ColorScheme
    
    // Deep Space is now the default
    static let defaultTheme = AppTheme(
        id: "default", // Original default ID
        name: "Deep Space (Default)",
        background: Color(hex: "0D1117"),
        surface: Color(hex: "161B22"),
        textPrimary: Color(hex: "F0F6FC"),
        textSecondary: Color(hex: "8B949E"),
        accent: Color(hex: "58A6FF"),
        border: Color(hex: "30363D"),
        success: Color(hex: "238636"),
        error: Color(hex: "DA3633"),
        colorScheme: .dark
    )
    
    static let matrixTheme = AppTheme(
        id: "hacker",
        name: "Matrix",
        background: Color(hex: "000000"),
        surface: Color(hex: "111111"),
        textPrimary: Color(hex: "00FF00"),
        textSecondary: Color(hex: "00FF00"),
        accent: Color(hex: "00FF00"),
        border: Color(hex: "00FF00"),
        success: Color(hex: "00FF00"),
        error: Color(hex: "FF0000"),
        colorScheme: .dark
    )
    
    static let oceanTheme = AppTheme(
        id: "ocean",
        name: "Ocean",
        background: Color(hex: "0F172A"),
        surface: Color(hex: "1E293B"),
        textPrimary: Color(hex: "F1F5F9"),
        textSecondary: Color(hex: "94A3B8"),
        accent: Color(hex: "38BDF8"),
        border: Color(hex: "334155"),
        success: Color(hex: "22C55E"),
        error: Color(hex: "EF4444"),
        colorScheme: .dark
    )
    
    static let sunsetTheme = AppTheme(
        id: "sunset",
        name: "Sunset",
        background: Color(hex: "2A1B1B"),
        surface: Color(hex: "4A2C2C"),
        textPrimary: Color(hex: "FDE047"),
        textSecondary: Color(hex: "FCA5A5"),
        accent: Color(hex: "F59E0B"),
        border: Color(hex: "7F1D1D"),
        success: Color(hex: "10B981"),
        error: Color(hex: "EF4444"),
        colorScheme: .dark
    )

    static let natureTheme = AppTheme(
        id: "nature",
        name: "Nature",
        background: Color(hex: "1A2F1A"),
        surface: Color(hex: "2C442C"),
        textPrimary: Color(hex: "D1FAE5"),
        textSecondary: Color(hex: "A7F3D0"),
        accent: Color(hex: "34D399"),
        border: Color(hex: "065F46"),
        success: Color(hex: "34D399"),
        error: Color(hex: "F87171"),
        colorScheme: .dark
    )
    
    static let glacierTheme = AppTheme(
        id: "glacier",
        name: "Glacier",
        background: Color(hex: "FFFFFF"),
        surface: Color(hex: "F5F5F5"),
        textPrimary: Color(hex: "1A1A1A"),
        textSecondary: Color(hex: "666666"),
        accent: Color(hex: "0EA5E9"),
        border: Color(hex: "E5E5E5"),
        success: Color(hex: "22C55E"),
        error: Color(hex: "EF4444"),
        colorScheme: .light
    )
    
    static let allThemes = [defaultTheme, matrixTheme, oceanTheme, sunsetTheme, natureTheme, glacierTheme]
}

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (1, 1, 1, 0)
        }

        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}
