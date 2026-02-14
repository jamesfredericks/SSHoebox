import Foundation

public enum GeneratorType: String, CaseIterable, Identifiable {
    case password = "Password"
    case passphrase = "Passphrase"
    
    public var id: String { self.rawValue }
}

public struct GeneratorOptions {
    public var length: Int = 16
    public var useUppercase: Bool = true
    public var useLowercase: Bool = true
    public var useDigits: Bool = true
    public var useSymbols: Bool = true
    public var avoidAmbiguous: Bool = false
    public var type: GeneratorType = .password
    public var passphraseWords: Int = 4
    public var separator: String = "-"
    
    public init() {}
}

public struct PasswordGenerator {
    
    private static let lowercase = "abcdefghijklmnopqrstuvwxyz"
    private static let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private static let digits = "0123456789"
    private static let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    private static let ambiguous = "O0l1I"
    
    // Simple word list for passphrase (normally this would be much larger)
    private static let wordList = [
        "apple", "brave", "crane", "drift", "eagle", "forest", "grape", "hill",
        "island", "jump", "kite", "lemon", "mountain", "nebula", "ocean", "piano",
        "quiet", "river", "stone", "train", "umbrella", "valley", "window", "xenon",
        "yellow", "zebra", "happy", "sunny", "swift", "code", "secure", "safe", "lock"
    ]
    
    public static func generate(options: GeneratorOptions) -> String {
        switch options.type {
        case .password:
            return generatePassword(options: options)
        case .passphrase:
            return generatePassphrase(options: options)
        }
    }
    
    private static func generatePassword(options: GeneratorOptions) -> String {
        var charset = ""
        var guaranteedChars = ""
        
        if options.useLowercase {
            charset += options.avoidAmbiguous ? removeAmbiguous(from: lowercase) : lowercase
            guaranteedChars.append(randomChar(from: options.avoidAmbiguous ? removeAmbiguous(from: lowercase) : lowercase))
        }
        if options.useUppercase {
            charset += options.avoidAmbiguous ? removeAmbiguous(from: uppercase) : uppercase
            guaranteedChars.append(randomChar(from: options.avoidAmbiguous ? removeAmbiguous(from: uppercase) : uppercase))
        }
        if options.useDigits {
            charset += options.avoidAmbiguous ? removeAmbiguous(from: digits) : digits
            guaranteedChars.append(randomChar(from: options.avoidAmbiguous ? removeAmbiguous(from: digits) : digits))
        }
        if options.useSymbols {
            charset += options.avoidAmbiguous ? removeAmbiguous(from: symbols) : symbols
            guaranteedChars.append(randomChar(from: options.avoidAmbiguous ? removeAmbiguous(from: symbols) : symbols))
        }
        
        // Fallback if nothing selected
        if charset.isEmpty {
            charset = lowercase
        }
        
        // Fill remaining length
        let remainingLength = max(0, options.length - guaranteedChars.count)
        var password = guaranteedChars
        
        for _ in 0..<remainingLength {
            password.append(randomChar(from: charset))
        }
        
        // Shuffle result
        return String(password.shuffled())
    }
    
    private static func generatePassphrase(options: GeneratorOptions) -> String {
        var words: [String] = []
        for _ in 0..<options.passphraseWords {
            if let word = wordList.randomElement() {
                words.append(word)
            }
        }
        // Apply simple capitalization if desired? 
        // For now, let's auto-capitalize logical first letter if separator is typical, or keep lowercase via logic.
        // Let's implement options later for passphrase specifics. Default to lowercase.
        return words.joined(separator: options.separator)
    }
    
    private static func removeAmbiguous(from source: String) -> String {
        return source.filter { !ambiguous.contains($0) }
    }
    
    private static func randomChar(from source: String) -> Character {
        return source.randomElement() ?? " "
    }
}
