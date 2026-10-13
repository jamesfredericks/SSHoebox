import XCTest
@testable import SSHoeboxCore

/// Covers the pieces of keyboard-interactive login that don't need a server: reading an answer
/// typed into the terminal, and spotting which prompt the stored password answers.
final class KeyboardInteractiveTests: XCTestCase {

    private func feed(_ reader: inout TerminalLineReader, _ text: String) -> (output: String, event: TerminalLineReader.Event) {
        let (output, event) = reader.feed(Data(text.utf8))
        return (String(decoding: output, as: UTF8.self), event)
    }

    // MARK: - TerminalLineReader

    func testSecretAnswerIsNotEchoed() {
        var reader = TerminalLineReader(echo: false)
        XCTAssertEqual(feed(&reader, "123").output, "")
        let result = feed(&reader, "456\r")
        XCTAssertEqual(result.output, "\r\n")
        XCTAssertEqual(result.event, .submitted("123456"))
    }

    func testEchoedAnswerIsShown() {
        var reader = TerminalLineReader(echo: true)
        XCTAssertEqual(feed(&reader, "ab").output, "ab")
        XCTAssertEqual(feed(&reader, "\r").event, .submitted("ab"))
    }

    func testBackspaceAndClearLineEdit() {
        var reader = TerminalLineReader(echo: true)
        _ = feed(&reader, "129")
        XCTAssertEqual(feed(&reader, "\u{7F}").output, "\u{08} \u{08}")
        XCTAssertEqual(feed(&reader, "3\r").event, .submitted("123"))

        var cleared = TerminalLineReader(echo: false)
        _ = feed(&cleared, "wrong")
        XCTAssertEqual(feed(&cleared, "\u{15}").output, "", "a secret prompt doesn't reveal the length")
        XCTAssertEqual(feed(&cleared, "right\n").event, .submitted("right"))
    }

    func testBackspaceOnEmptyLineDoesNothing() {
        var reader = TerminalLineReader(echo: true)
        XCTAssertEqual(feed(&reader, "\u{7F}").output, "")
        XCTAssertEqual(feed(&reader, "\r").event, .submitted(""))
    }

    func testCtrlCAndCtrlDCancel() {
        var reader = TerminalLineReader(echo: false)
        _ = feed(&reader, "12")
        XCTAssertEqual(feed(&reader, "\u{03}").event, .cancelled)

        var eof = TerminalLineReader(echo: false)
        XCTAssertEqual(feed(&eof, "\u{04}").event, .cancelled)
    }

    func testEscapeSequencesAndControlCharactersAreIgnored() {
        var reader = TerminalLineReader(echo: true)
        XCTAssertEqual(feed(&reader, "\u{1B}[A").output, "", "arrow keys are dropped")
        XCTAssertEqual(feed(&reader, "1\t2").output, "12")
        XCTAssertEqual(feed(&reader, "\r").event, .submitted("12"))
    }

    func testPasteWithTrailingNewlineSubmitsAndDropsTheRest() {
        var reader = TerminalLineReader(echo: false)
        XCTAssertEqual(feed(&reader, "654321\r\nextra").event, .submitted("654321"))
    }

    // MARK: - Password prompt detection

    func testPasswordPromptsAreRecognised() {
        for prompt in ["Password: ", "password:", "prod_user@jump's password: ", "Enter PASSWORD for prod_user: "] {
            XCTAssertTrue(KeyboardInteractiveAuthenticator.isPasswordPrompt(prompt), prompt)
        }
    }

    func testOneTimeCodePromptsAreNotFilledWithThePassword() {
        for prompt in [
            "Verification code: ",
            "One-time password (OATH) for `prod_user': ",
            "OTP password: ",
            "Passcode or option (1-3): ",
            "Enter your token password: ",
            "New password: ",
            "YubiKey for `prod_user': ",
        ] {
            XCTAssertFalse(KeyboardInteractiveAuthenticator.isPasswordPrompt(prompt), prompt)
        }
    }
}
