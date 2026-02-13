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
    
    // Matrix is now the default
    static let defaultTheme = AppTheme(
        id: "hacker", // Re-using hacker ID for consistency
        name: "Matrix (Default)",
        background: Color(hex: "000000"),
        surface: Color(hex: "111111"),
        textPrimary: Color(hex: "00FF00"),
        textSecondary: Color(hex: "00FF00"),
        accent: Color(hex: "00FF00"),
        border: Color(hex: "00FF00"),
        success: Color(hex: "00FF00"),
        error: Color(hex: "FF0000")
    )
    
    static let deepSpaceTheme = AppTheme(
        id: "default", // Original default
        name: "Deep Space",
        background: Color(hex: "0D1117"),
        surface: Color(hex: "161B22"),
        textPrimary: Color(hex: "F0F6FC"),
        textSecondary: Color(hex: "8B949E"),
        accent: Color(hex: "58A6FF"),
        border: Color(hex: "30363D"),
        success: Color(hex: "238636"),
        error: Color(hex: "DA3633")
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
        error: Color(hex: "EF4444")
    )
    
    static let sunsetTheme = AppTheme(
        id: "sunset",
        name: "Sunset",
        background: Color(hex: "2D1B2E"),
        surface: Color(hex: "462A48"),
        textPrimary: Color(hex: "FFD8C9"),
        textSecondary: Color(hex: "BFA0AA"),
        accent: Color(hex: "FF9E64"),
        border: Color(hex: "5C3A5E"),
        success: Color(hex: "9ECE6A"),
        error: Color(hex: "F7768E")
    )
    
    static let natureTheme = AppTheme(
        id: "nature",
        name: "Nature",
        background: Color(hex: "1B3A26"), 
        surface: Color(hex: "264D34"),    
        textPrimary: Color(hex: "ECFDF5"), 
        textSecondary: Color(hex: "A7F3D0"), 
        accent: Color(hex: "34D399"),     
        border: Color(hex: "059669"),     
        success: Color(hex: "4ADE80"),    
        error: Color(hex: "F87171")       
    )
    
    static let allThemes = [defaultTheme, deepSpaceTheme, oceanTheme, sunsetTheme, natureTheme]
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
