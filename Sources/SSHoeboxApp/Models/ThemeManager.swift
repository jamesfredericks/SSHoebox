import SwiftUI
import Combine

class ThemeManager: ObservableObject {
    @Published var currentTheme: AppTheme {
        didSet {
            UserDefaults.standard.set(currentTheme.id, forKey: "selectedThemeId")
        }
    }

    @Published var terminalFontSize: CGFloat {
        didSet {
            UserDefaults.standard.set(Double(terminalFontSize), forKey: "terminalFontSize")
        }
    }

    static let shared = ThemeManager()

    private init() {
        let savedThemeId = UserDefaults.standard.string(forKey: "selectedThemeId") ?? AppTheme.defaultTheme.id
        self.currentTheme = AppTheme.allThemes.first(where: { $0.id == savedThemeId }) ?? AppTheme.defaultTheme
        let savedSize = UserDefaults.standard.double(forKey: "terminalFontSize")
        self.terminalFontSize = savedSize > 0 ? CGFloat(savedSize) : 13
    }

    func setTheme(id: String) {
        if let theme = AppTheme.allThemes.first(where: { $0.id == id }) {
            withAnimation {
                currentTheme = theme
            }
        }
    }

    func increaseFontSize() {
        terminalFontSize = min(terminalFontSize + 1, 32)
    }

    func decreaseFontSize() {
        terminalFontSize = max(terminalFontSize - 1, 8)
    }
}
