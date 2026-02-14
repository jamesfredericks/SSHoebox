import SwiftUI

public struct TerminalTheme: Identifiable, Hashable {
    public var id: String { name }
    public var name: String
    public var backgroundColor: Color
    public var foregroundColor: Color
    public var cursorColor: Color
    public var fontName: String
    public var fontSize: CGFloat
    
    public static let matrix = TerminalTheme(
        name: "Matrix",
        backgroundColor: .black,
        foregroundColor: .green,
        cursorColor: .green,
        fontName: "Menlo",
        fontSize: 14
    )
    
    public static let ocean = TerminalTheme(
        name: "Ocean",
        backgroundColor: Color(nsColor: NSColor(red: 0.1, green: 0.1, blue: 0.3, alpha: 1.0)),
        foregroundColor: .white,
        cursorColor: .cyan,
        fontName: "Monaco",
        fontSize: 14
    )
    
    public static let sunset = TerminalTheme(
        name: "Sunset",
        backgroundColor: Color(nsColor: NSColor(red: 0.2, green: 0.1, blue: 0.1, alpha: 1.0)),
        foregroundColor: .orange,
        cursorColor: .red,
        fontName: "Courier New",
        fontSize: 14
    )
    
    public static let allThemes = [matrix, ocean, sunset]
}

public class ThemeManager: ObservableObject {
    @Published public var currentTheme: TerminalTheme = .matrix
    
    public init() {}
}
