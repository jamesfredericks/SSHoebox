import Foundation

/// Collects one line typed into the terminal before a shell exists, such as the answer to a
/// keyboard-interactive prompt ("Verification code: "). Like OpenSSH, secret answers aren't echoed.
struct TerminalLineReader {

    enum Event: Equatable {
        /// More input is needed.
        case pending
        /// Return was pressed; the line is complete.
        case submitted(String)
        /// Ctrl-C or Ctrl-D was pressed.
        case cancelled
    }

    let echo: Bool
    private var line: [Character] = []

    init(echo: Bool) {
        self.echo = echo
    }

    /// Feeds keystrokes (or a paste) to the reader. Returns what to write back to the terminal
    /// and whether the line is finished. Input after Return or Ctrl-C is dropped.
    mutating func feed(_ data: Data) -> (output: Data, event: Event) {
        // Arrow and function keys arrive as escape sequences; there's no cursor to move, so drop them.
        if data.contains(0x1B) { return (Data(), .pending) }

        var output = ""
        for character in String(decoding: data, as: UTF8.self) {
            switch character {
            case "\r", "\n", "\r\n":
                output += "\r\n"
                return (Data(output.utf8), .submitted(String(line)))
            case "\u{03}", "\u{04}":
                output += "^C\r\n"
                return (Data(output.utf8), .cancelled)
            case "\u{7F}", "\u{08}":
                if !line.isEmpty {
                    line.removeLast()
                    if echo { output += "\u{08} \u{08}" }
                }
            case "\u{15}":
                if echo { output += String(repeating: "\u{08} \u{08}", count: line.count) }
                line.removeAll()
            default:
                guard !character.unicodeScalars.allSatisfy({ $0.value < 0x20 }) else { continue }
                line.append(character)
                if echo { output.append(character) }
            }
        }
        return (Data(output.utf8), .pending)
    }
}
