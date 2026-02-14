import SwiftUI
import Combine

class ThemeManager: ObservableObject {
    @Published var currentTheme: AppTheme {
        didSet {
            UserDefaults.standard.set(currentTheme.id, forKey: "selectedThemeId")
        }
    }
    
    static let shared = ThemeManager()
    
    private init() {
        let savedThemeId = UserDefaults.standard.string(forKey: "selectedThemeId") ?? AppTheme.defaultTheme.id
        self.currentTheme = AppTheme.allThemes.first(where: { $0.id == savedThemeId }) ?? AppTheme.defaultTheme
    }
    
    func setTheme(id: String) {
        if let theme = AppTheme.allThemes.first(where: { $0.id == id }) {
            withAnimation {
                currentTheme = theme
            }
        }
    }
}
