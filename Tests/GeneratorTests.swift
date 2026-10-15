import XCTest
@testable import SSHoeboxCore

final class GeneratorTests: XCTestCase {

    func testPasswordLength() {
        var options = GeneratorOptions()
        options.length = 25
        let password = PasswordGenerator.generate(options: options)
        XCTAssertEqual(password.count, 25)
    }

    func testPasswordShorterThanEnabledSetsHonoursLength() {
        var options = GeneratorOptions()
        options.length = 2 // fewer than the 4 enabled character sets
        XCTAssertEqual(PasswordGenerator.generate(options: options).count, 2)
    }

    func testPasswordCharacterSets() {
        var options = GeneratorOptions()
        options.useUppercase = false
        options.useDigits = false
        options.useSymbols = false
        options.useLowercase = true

        let password = PasswordGenerator.generate(options: options)
        // Should only contain lowercase
        let charset = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz")
        XCTAssertTrue(password.rangeOfCharacter(from: charset.inverted) == nil)
    }

    func testPassphraseWordCount() {
        var options = GeneratorOptions()
        options.type = .passphrase
        options.passphraseWords = 5
        // Not "-": a few EFF words contain a hyphen ("t-shirt")
        options.separator = "."

        let password = PasswordGenerator.generate(options: options)
        let components = password.components(separatedBy: ".")
        XCTAssertEqual(components.count, 5)
        let words = Set(PasswordGenerator.wordList)
        for component in components {
            XCTAssertTrue(words.contains(component), "\(component) not in wordlist")
        }
    }

    func testPassphraseDefaultsToSixWords() {
        var options = GeneratorOptions()
        options.type = .passphrase
        XCTAssertEqual(options.passphraseWords, 6)
        options.separator = " "
        XCTAssertEqual(PasswordGenerator.generate(options: options).components(separatedBy: " ").count, 6)
    }

    func testWordlistIsEFFLargeList() {
        let words = PasswordGenerator.wordList
        XCTAssertEqual(words.count, 7776)
        XCTAssertEqual(Set(words).count, 7776, "wordlist contains duplicates")
        XCTAssertEqual(words.first, "abacus")
        XCTAssertEqual(words.last, "zoom")
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz-").inverted
        for word in words {
            XCTAssertFalse(word.isEmpty)
            XCTAssertNil(word.rangeOfCharacter(from: allowed), "unexpected character in \(word)")
        }
    }

    func testEntropyEstimate() {
        var options = GeneratorOptions()
        options.type = .passphrase
        options.passphraseWords = 6
        XCTAssertEqual(PasswordGenerator.entropyBits(options: options), 6 * log2(7776.0), accuracy: 0.001)
        XCTAssertGreaterThan(PasswordGenerator.entropyBits(options: options), 77)

        options.type = .password
        options.length = 16
        options.useUppercase = false
        options.useDigits = false
        options.useSymbols = false
        XCTAssertEqual(PasswordGenerator.entropyBits(options: options), 16 * log2(26.0), accuracy: 0.001)
    }

    func testAmbiguousExclusion() {
        var options = GeneratorOptions()
        options.type = .password
        options.avoidAmbiguous = true
        options.length = 100 // Generate long one to increase chance of hitting ambiguous chars if they weren't removed

        let password = PasswordGenerator.generate(options: options)
        // O0l1I
        let ambiguous = CharacterSet(charactersIn: "O0l1I")
        XCTAssertTrue(password.rangeOfCharacter(from: ambiguous) == nil)
    }
}
