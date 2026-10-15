import Foundation

/// RFC 4180 CSV parser.
///
/// - Fields may be quoted with `"`; inside quotes, commas, CR, LF and CRLF are literal and
///   `""` is an escaped quote. Quoted content is never trimmed or otherwise altered.
/// - Records end at CRLF, LF or a lone CR. A trailing line break does not add a record.
/// - A leading UTF-8 byte order mark is ignored.
/// - Lenient where real-world exporters are sloppy: a `"` inside an unquoted field, or text
///   after a closing quote, is kept literally.
///
/// Works on Unicode scalars rather than Characters, because Swift treats "\r\n" (and a quote
/// followed by a combining mark) as a single Character.
public enum CSVParser {

    public enum ParseError: LocalizedError, Equatable {
        /// A quoted field was still open at the end of the input. `line` is 1-based.
        case unterminatedQuote(line: Int)

        public var errorDescription: String? {
            switch self {
            case .unterminatedQuote(let line):
                return "The CSV file has a quoted field starting on line \(line) that is never closed."
            }
        }
    }

    public static func parse(_ text: String) throws -> [[String]] {
        var scalars = text.unicodeScalars[...]
        if scalars.first == "\u{FEFF}" { scalars = scalars.dropFirst() }

        var records: [[String]] = []
        var record: [String] = []
        var field = String.UnicodeScalarView()
        var inQuotes = false
        var afterClosingQuote = false
        var line = 1
        var quoteStartLine = 1

        func endField() {
            record.append(String(field))
            field = String.UnicodeScalarView()
            afterClosingQuote = false
        }
        func endRecord() {
            endField()
            records.append(record)
            record = []
        }

        var i = scalars.startIndex
        while i < scalars.endIndex {
            let c = scalars[i]
            let next = scalars.index(after: i)

            if inQuotes {
                if c == "\"" {
                    if next < scalars.endIndex && scalars[next] == "\"" {
                        field.append("\"")      // escaped quote
                        i = scalars.index(after: next)
                        continue
                    }
                    inQuotes = false
                    afterClosingQuote = true
                } else {
                    if c == "\n" || (c == "\r" && !(next < scalars.endIndex && scalars[next] == "\n")) {
                        line += 1
                    }
                    field.append(c)
                }
                i = next
                continue
            }

            switch c {
            case ",":
                endField()
            case "\r", "\n":
                endRecord()
                line += 1
                if c == "\r" && next < scalars.endIndex && scalars[next] == "\n" {
                    i = scalars.index(after: next)
                    continue
                }
            case "\"" where field.isEmpty && !afterClosingQuote:
                inQuotes = true
                quoteStartLine = line
            default:
                field.append(c)
            }
            i = next
        }

        if inQuotes { throw ParseError.unterminatedQuote(line: quoteStartLine) }
        // Flush the last record unless the input ended with a line break
        if !field.isEmpty || !record.isEmpty || afterClosingQuote {
            endRecord()
        }
        return records
    }
}
