import XCTest
@testable import SSHoeboxCore

final class SessionRecorderTests: XCTestCase {
    private func strip(_ chunks: [String]) -> String {
        var stripper = TerminalTextStripper()
        return chunks.map { stripper.feed(Data($0.utf8)) }.joined() + stripper.flush()
    }

    func testRemovesEscapeSequencesAndKeepsText() {
        let colored = "\u{1B}[1;32muser@host\u{1B}[0m:\u{1B}[01;34m~\u{1B}[0m$ ls\r\n"
        XCTAssertEqual(strip([colored]), "user@host:~$ ls\n")
        let title = "\u{1B}]0;user@host: ~\u{07}prompt$ "
        XCTAssertEqual(strip([title]), "prompt$ ")
        let st = "\u{1B}]8;;https://x\u{1B}\\link\u{1B}]8;;\u{1B}\\ done\n"
        XCTAssertEqual(strip([st]), "link done\n")
        XCTAssertEqual(strip(["\u{1B}(Bplain\n"]), "plain\n")
    }

    func testCarriageReturnOverwritesAndBackspaceDeletes() {
        XCTAssertEqual(strip(["10%\r50%\r100%\n"]), "100%\n")
        XCTAssertEqual(strip(["abc\u{08}\u{08}d\n"]), "ad\n")
        XCTAssertEqual(strip(["héé\u{08}\n"]), "hé\n", "a backspace removes a whole UTF-8 character")
    }

    func testKeepsUTF8SplitAcrossChunks() {
        let bytes = Array("naïve ✓\n".utf8)
        var stripper = TerminalTextStripper()
        var text = ""
        for byte in bytes { text += stripper.feed(Data([byte])) }
        XCTAssertEqual(text, "naïve ✓\n")
        XCTAssertEqual(strip(["\r", "\n"]), "\n", "CR and LF in separate chunks")
    }

    func testWritesAPrivateFileWithHeaderAndFooter() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        let recorder = try SessionRecorder(directory: folder, hostName: "web/prod", endpoint: "deploy@web:22")
        recorder.record(Data("\u{1B}[32mhello\u{1B}[0m\r\nlast".utf8))
        recorder.finish()
        let text = try String(contentsOf: recorder.fileURL, encoding: .utf8)
        XCTAssertTrue(text.contains("Host:    web/prod (deploy@web:22)"))
        XCTAssertTrue(text.contains("hello\nlast\n"))
        XCTAssertTrue(text.contains("Ended:"))
        XCTAssertFalse(recorder.fileURL.lastPathComponent.contains("/"))
        let mode = try FileManager.default.attributesOfItem(atPath: recorder.fileURL.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)

        let second = try SessionRecorder(directory: folder, hostName: "web/prod", endpoint: "x",
                                         date: Date())
        XCTAssertNotEqual(second.fileURL, recorder.fileURL, "never overwrites an earlier recording")
    }
}
