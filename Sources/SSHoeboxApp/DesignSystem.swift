import SwiftUI

struct DesignSystem {
    // MARK: - Colors
    struct Colors {
        static var background: Color { ThemeManager.shared.currentTheme.background }
        static var surface: Color { ThemeManager.shared.currentTheme.surface }
        static var textPrimary: Color { ThemeManager.shared.currentTheme.textPrimary }
        static var textSecondary: Color { ThemeManager.shared.currentTheme.textSecondary }
        static var accent: Color { ThemeManager.shared.currentTheme.accent }
        static var border: Color { ThemeManager.shared.currentTheme.border }
        static var success: Color { ThemeManager.shared.currentTheme.success }
        static var error: Color { ThemeManager.shared.currentTheme.error }
    }
    
    // MARK: - Typography
    struct Typography {
        static let fontName = "Inter-Regular" // Assuming Inter is available or fallback to system
        
        static func hero() -> Font {
            .system(size: 32, weight: .bold, design: .default)
        }
        
        static func heading() -> Font {
            .system(size: 16, weight: .semibold, design: .default)
        }
        
        static func body() -> Font {
            .system(size: 14, weight: .regular, design: .default)
        }
        
        static func label() -> Font {
            .system(size: 12, weight: .medium, design: .default)
        }
        
        static func mono() -> Font {
            .system(size: 13, weight: .regular, design: .monospaced)
        }
    }
    
    // MARK: - Spacing
    struct Spacing {
        static let tight: CGFloat = 4
        static let standard: CGFloat = 8
        static let medium: CGFloat = 16
        static let large: CGFloat = 24
        static let extraLarge: CGFloat = 32
    }
    
    // MARK: - Radius
    struct Radius {
        static let sm: CGFloat = 4
        static let md: CGFloat = 8
        static let lg: CGFloat = 12
        static let xl: CGFloat = 16
        static let full: CGFloat = 9999
    }
    
    // MARK: - Animation
    struct Animation {
        static let hover = SwiftUI.Animation.easeInOut(duration: 0.2)
        static let press = SwiftUI.Animation.easeInOut(duration: 0.1)
    }
}
