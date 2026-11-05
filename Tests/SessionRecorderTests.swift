import XCTest
import CryptoKit
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

    // MARK: - Encrypted recordings

    private let vaultKey = SymmetricKey(size: .bits256)
    private var folder: URL!

    override func setUpWithError() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: folder)
    }

    private func makeRecording(_ chunks: [String], finish: Bool = true) throws -> URL {
        let recorder = try SessionRecorder(directory: folder, hostName: "prod-db-01", endpoint: "admin@10.1.2.3:22",
                                           vaultKey: vaultKey)
        for chunk in chunks {
            recorder.record(Data(chunk.utf8))
            recorder.flush()
        }
        if finish { recorder.finish() }
        return recorder.fileURL
    }

    func testRoundTripsAndNothingIsReadableOnDisk() throws {
        let url = try makeRecording(["\u{1B}[32mSECRET-OUTPUT\u{1B}[0m line one\r\n", "line two\r\nlast"])
        let raw = try Data(contentsOf: url)
        for clear in ["SECRET-OUTPUT", "line one", "prod-db-01", "10.1.2.3", "admin"] {
            XCTAssertNil(raw.range(of: Data(clear.utf8)), "\(clear) must not appear in the file")
        }
        XCTAssertFalse(url.lastPathComponent.contains("prod"), "the file name doesn't reveal the host")
        XCTAssertEqual(url.pathExtension, "sshrec")

        let contents = try SessionRecordingReader.read(url, vaultKey: vaultKey)
        XCTAssertEqual(contents.metadata.hostName, "prod-db-01")
        XCTAssertEqual(contents.metadata.endpoint, "admin@10.1.2.3:22")
        XCTAssertEqual(contents.text, "SECRET-OUTPUT line one\nline two\nlast\n")
        XCTAssertTrue(contents.isComplete)
        XCTAssertNotNil(contents.endedAt)

        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
        let dirMode = try FileManager.default.attributesOfItem(atPath: folder.path)[.posixPermissions] as? Int
        XCTAssertEqual(dirMode, 0o700)
    }

    func testAnotherVaultsKeyCantOpenIt() throws {
        let url = try makeRecording(["hello\n"])
        XCTAssertThrowsError(try SessionRecordingReader.read(url, vaultKey: SymmetricKey(size: .bits256))) { error in
            XCTAssertEqual(error as? SessionRecordingReader.ReadError, .wrongKey)
        }
        let listed = SessionRecording.list(in: folder, vaultKey: SymmetricKey(size: .bits256))
        XCTAssertEqual(listed.count, 1)
        XCTAssertNil(listed[0].metadata, "listed, but unreadable")
        XCTAssertEqual(SessionRecording.list(in: folder, vaultKey: vaultKey).first?.metadata?.hostName, "prod-db-01")
    }

    func testTamperingAndTruncationAreDetected() throws {
        let url = try makeRecording(["first\n", "second\n", "third\n"])
        let raw = try Data(contentsOf: url)
        let chunks = Self.chunkRanges(raw)
        XCTAssertEqual(chunks.count, 5, "metadata, three text chunks, end")

        // Flip one byte in the third text chunk: reading stops before it and says incomplete.
        var tampered = raw
        tampered[chunks[3].upperBound - 5] ^= 0x01
        try tampered.write(to: url)
        let afterTamper = try SessionRecordingReader.read(url, vaultKey: vaultKey)
        XCTAssertFalse(afterTamper.isComplete)
        XCTAssertFalse(afterTamper.text.contains("third"))

        // Cut off the end marker (the app quit mid-recording): the text so far, marked incomplete.
        try raw.prefix(chunks[chunks.count - 1].lowerBound).write(to: url)
        let truncated = try SessionRecordingReader.read(url, vaultKey: vaultKey)
        XCTAssertEqual(truncated.text, "first\nsecond\nthird\n")
        XCTAssertFalse(truncated.isComplete)

        // Swap two chunks: the second one out of place doesn't authenticate.
        var swapped = Data(raw.prefix(chunks[1].lowerBound))
        swapped.append(raw.subdata(in: chunks[2]))
        swapped.append(raw.subdata(in: chunks[1]))
        swapped.append(raw.subdata(in: chunks[3].lowerBound..<raw.count))
        try swapped.write(to: url)
        let reordered = try SessionRecordingReader.read(url, vaultKey: vaultKey)
        XCTAssertEqual(reordered.text, "", "nothing after the misplaced chunk is trusted")
        XCTAssertFalse(reordered.isComplete)
    }

    func testOutputIsBufferedIntoFewChunks() throws {
        let recorder = try SessionRecorder(directory: folder, hostName: "h", endpoint: "e", vaultKey: vaultKey)
        for _ in 0..<100 { recorder.record(Data("x\n".utf8)) }
        recorder.finish()
        let chunks = Self.chunkRanges(try Data(contentsOf: recorder.fileURL))
        XCTAssertLessThanOrEqual(chunks.count, 4, "metadata, text, end: not one chunk per write")
        XCTAssertEqual(try SessionRecordingReader.read(recorder.fileURL, vaultKey: vaultKey).text.count, 200)
    }

    func testRejectsFilesThatArentRecordings() throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appendingPathComponent("x.sshrec")
        try Data("hello world, not a recording".utf8).write(to: url)
        XCTAssertThrowsError(try SessionRecordingReader.read(url, vaultKey: vaultKey)) { error in
            XCTAssertEqual(error as? SessionRecordingReader.ReadError, .notARecording)
        }
    }

    /// Byte ranges of each length-prefixed chunk after the 24-byte header.
    private static func chunkRanges(_ data: Data) -> [Range<Int>] {
        var ranges: [Range<Int>] = []
        var offset = 24
        let bytes = [UInt8](data)
        while offset + 4 <= bytes.count {
            let length = bytes[offset..<(offset + 4)].reduce(0) { $0 << 8 | Int($1) }
            ranges.append(offset..<min(bytes.count, offset + 4 + length))
            offset += 4 + length
        }
        return ranges
    }
}
