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
    /// 6 EFF words is ~77.5 bits of entropy.
    public var passphraseWords: Int = 6
    public var separator: String = "-"

    public init() {}
}

public struct PasswordGenerator {

    private static let lowercase = "abcdefghijklmnopqrstuvwxyz"
    private static let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private static let digits = "0123456789"
    private static let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    private static let ambiguous = "O0l1I"

    /// EFF large wordlist (7,776 words, ~12.9 bits per word).
    static var wordList: [String] { EFFWordlist.words }

    public static func generate(options: GeneratorOptions) -> String {
        switch options.type {
        case .password:
            return generatePassword(options: options)
        case .passphrase:
            return generatePassphrase(options: options)
        }
    }

    /// Approximate entropy of a value generated with `options`, in bits.
    /// Passwords: length x log2(charset size) (slightly generous, since one
    /// character from each enabled set is guaranteed). Passphrases:
    /// words x log2(7,776).
    public static func entropyBits(options: GeneratorOptions) -> Double {
        switch options.type {
        case .password:
            let size = characterSets(options: options).joined().count
            return Double(max(0, options.length)) * log2(Double(size))
        case .passphrase:
            return Double(max(0, options.passphraseWords)) * log2(Double(wordList.count))
        }
    }

    /// The enabled character sets, with ambiguous characters removed if requested.
    /// Falls back to lowercase if nothing is enabled.
    private static func characterSets(options: GeneratorOptions) -> [String] {
        var sets: [String] = []
        if options.useLowercase { sets.append(lowercase) }
        if options.useUppercase { sets.append(uppercase) }
        if options.useDigits { sets.append(digits) }
        if options.useSymbols { sets.append(symbols) }
        if sets.isEmpty { sets.append(lowercase) }
        return options.avoidAmbiguous ? sets.map(removeAmbiguous(from:)) : sets
    }

    private static func generatePassword(options: GeneratorOptions) -> String {
        var rng = SystemRandomNumberGenerator()
        let length = max(0, options.length)
        let sets = characterSets(options: options)
        let charset = sets.joined()

        // One character from each enabled set, then fill the remaining length
        var password = sets.prefix(length).map { randomChar(from: $0, using: &rng) }
        while password.count < length {
            password.append(randomChar(from: charset, using: &rng))
        }

        // Shuffle so the guaranteed characters aren't always at the front
        password.shuffle(using: &rng)
        return String(password)
    }

    private static func generatePassphrase(options: GeneratorOptions) -> String {
        var rng = SystemRandomNumberGenerator()
        let words = (0..<max(0, options.passphraseWords)).compactMap { _ in
            wordList.randomElement(using: &rng)
        }
        // Four EFF words contain a hyphen (e.g. "t-shirt"), so a hyphen-separated
        // passphrase can't always be split back into words. This doesn't
        // meaningfully reduce entropy.
        return words.joined(separator: options.separator)
    }

    private static func removeAmbiguous(from source: String) -> String {
        return source.filter { !ambiguous.contains($0) }
    }

    private static func randomChar(from source: String, using rng: inout SystemRandomNumberGenerator) -> Character {
        return source.randomElement(using: &rng) ?? " "
    }
}
