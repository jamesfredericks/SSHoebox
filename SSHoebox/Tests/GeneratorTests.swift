import XCTest
@testable import SSHoeboxCore

final class GeneratorTests: XCTestCase {
    
    func testPasswordLength() {
        var options = GeneratorOptions()
        options.length = 25
        let password = PasswordGenerator.generate(options: options)
        XCTAssertEqual(password.count, 25)
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
        options.separator = "-"
        
        let password = PasswordGenerator.generate(options: options)
        let components = password.components(separatedBy: "-")
        XCTAssertEqual(components.count, 5)
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
