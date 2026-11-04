import XCTest
import SSHoeboxCore
@testable import SSHoeboxApp

@MainActor
final class LoginLogStoreTests: XCTestCase {
    func testFiltersByAttemptLevelAndText() {
        let buffer = LoginLogBuffer()
        buffer.append(level: .info, line: "[aaaa1111 +0ms] SSH login to alpha:22 as \"root\"")
        buffer.append(level: .error, line: "[aaaa1111 +9ms] failed: connection refused")
        buffer.append(level: .info, line: "[bbbb2222 +0ms] SSH login to beta:22 as \"deploy\"")
        buffer.append(level: .error, line: "[-] credential 7: stored password could not be decrypted")
        let store = LoginLogStore(buffer: buffer)

        XCTAssertEqual(store.visibleEntries(search: "", errorsOnly: false).count, 4)
        XCTAssertEqual(store.visibleEntries(search: "", errorsOnly: true).count, 2)
        XCTAssertEqual(store.visibleEntries(search: "BETA", errorsOnly: false).map(\.attemptID), ["bbbb2222"])

        store.focusedAttemptID = "aaaa1111"
        XCTAssertEqual(store.visibleEntries(search: "", errorsOnly: false).count, 2)
        XCTAssertEqual(store.visibleEntries(search: "", errorsOnly: true).map(\.line),
                       ["[aaaa1111 +9ms] failed: connection refused"])
    }

    func testFollowsTheBufferAndClears() async throws {
        let buffer = LoginLogBuffer()
        let store = LoginLogStore(buffer: buffer)
        buffer.append(level: .info, line: "[cccc3333 +0ms] hello")
        let updated = expectation(forNotification: LoginLogBuffer.didChange, object: buffer)
        await fulfillment(of: [updated], timeout: 2)
        XCTAssertEqual(store.entries.count, 1)

        store.focusedAttemptID = "cccc3333"
        store.clear()
        XCTAssertTrue(store.entries.isEmpty)
        XCTAssertTrue(buffer.entries.isEmpty)
        XCTAssertNil(store.focusedAttemptID)
    }

    func testCopiedTextMarksErrors() {
        let buffer = LoginLogBuffer()
        buffer.append(level: .error, line: "[x +0ms] boom")
        XCTAssertTrue(LoginLogStore.text(of: buffer.entries).contains("ERROR [x +0ms] boom"))
    }
}
