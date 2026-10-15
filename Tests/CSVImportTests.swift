import XCTest
@testable import SSHoeboxCore

final class CSVParserTests: XCTestCase {

    func testSimpleRecords() throws {
        XCTAssertEqual(try CSVParser.parse("a,b,c\n1,2,3\n"), [["a", "b", "c"], ["1", "2", "3"]])
    }

    func testNoTrailingNewline() throws {
        XCTAssertEqual(try CSVParser.parse("a,b\n1,2"), [["a", "b"], ["1", "2"]])
    }

    func testEmptyInput() throws {
        XCTAssertEqual(try CSVParser.parse(""), [])
    }

    func testEmptyFields() throws {
        XCTAssertEqual(try CSVParser.parse("a,,c,\n,,\n"), [["a", "", "c", ""], ["", "", ""]])
        XCTAssertEqual(try CSVParser.parse("\"\""), [[""]])
    }

    func testCRLFAndLoneCR() throws {
        XCTAssertEqual(try CSVParser.parse("a,b\r\n1,2\r\n"), [["a", "b"], ["1", "2"]])
        XCTAssertEqual(try CSVParser.parse("a,b\r1,2\r"), [["a", "b"], ["1", "2"]])
    }

    func testQuotedFieldWithCommaAndEscapedQuote() throws {
        XCTAssertEqual(try CSVParser.parse("\"a,b\",\"say \"\"hi\"\"\",\"\"\"\"\n"),
                       [["a,b", "say \"hi\"", "\""]])
    }

    func testQuotedFieldWithEmbeddedNewlines() throws {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nAAAA\nBBBB\r\n-----END OPENSSH PRIVATE KEY-----\n"
        let csv = "name,secret\r\nweb,\"\(key)\"\r\nnext,x\r\n"
        XCTAssertEqual(try CSVParser.parse(csv), [["name", "secret"], ["web", key], ["next", "x"]])
    }

    func testWhitespaceIsPreserved() throws {
        XCTAssertEqual(try CSVParser.parse(" a , b ,\"  c  \"\n"), [[" a ", " b ", "  c  "]])
    }

    func testBOMIsStripped() throws {
        XCTAssertEqual(try CSVParser.parse("\u{FEFF}name,url\nx,y\n"), [["name", "url"], ["x", "y"]])
    }

    func testLenientStrayQuotes() throws {
        // Quote inside an unquoted field, and text after a closing quote, are kept literally
        XCTAssertEqual(try CSVParser.parse("ab\"cd,\"ef\"gh\n"), [["ab\"cd", "efgh"]])
    }

    func testUnterminatedQuoteThrows() {
        XCTAssertThrowsError(try CSVParser.parse("a,b\n1,\"open\n2,3\n")) { error in
            XCTAssertEqual(error as? CSVParser.ParseError, .unterminatedQuote(line: 2))
        }
    }

    func testQuoteFollowedByCombiningMarkIsStillAQuote() throws {
        // "\"\u{301}" is a single Swift Character; parsing must work on scalars
        XCTAssertEqual(try CSVParser.parse("\"x\",\"\u{301}y\"\n"), [["x", "\u{301}y"]])
    }

    func testBlankLinesBecomeEmptyRecords() throws {
        XCTAssertEqual(try CSVParser.parse("a\n\nb\n"), [["a"], [""], ["b"]])
    }
}

final class CredentialImporterTests: XCTestCase {

    // MARK: CSV formats

    func testSSHoeboxFormatWithHeader() throws {
        let entries = try CredentialImporter.parseCSV("""
        name,hostname,port,username,password
        Web,web.example.com,2222,deploy,s3cret
        DB,10.0.0.5,,root,
        """)
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries[0].name, "Web")
        XCTAssertEqual(entries[0].hostname, "web.example.com")
        XCTAssertEqual(entries[0].port, 2222)
        XCTAssertEqual(entries[0].username, "deploy")
        XCTAssertEqual(entries[0].password, "s3cret")
        XCTAssertEqual(entries[1].port, 22)
        XCTAssertEqual(entries[1].password, "")
    }

    func testHeaderlessFileIsReadPositionally() throws {
        let entries = try CredentialImporter.parseCSV("Web,web.example.com,2200,deploy,pw\n")
        XCTAssertEqual(entries.count, 1, "first row is data when it isn't a recognised header")
        XCTAssertEqual(entries[0].hostname, "web.example.com")
        XCTAssertEqual(entries[0].port, 2200)
        XCTAssertEqual(entries[0].password, "pw")
    }

    func testColumnsAreMappedByHeaderNotPosition() throws {
        let entries = try CredentialImporter.parseCSV("""
        Password,Port,User Name,Host,Title
        pw,2022,alice,box.example.com,Box
        """)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].name, "Box")
        XCTAssertEqual(entries[0].hostname, "box.example.com")
        XCTAssertEqual(entries[0].port, 2022)
        XCTAssertEqual(entries[0].username, "alice")
        XCTAssertEqual(entries[0].password, "pw")
    }

    func testBitwardenCSV() throws {
        let csv = """
        folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\r
        Servers,,login,Prod box,"line one\r
        line two",,0,"ssh://prod.example.com:2200,https://prod.example.com",admin,"p,a""ss word ",\r
        ,,note,Just a note,secret note,,0,,,,\r
        """
        let entries = try CredentialImporter.parseCSV(csv)
        XCTAssertEqual(entries.count, 1)
        let e = try XCTUnwrap(entries.first)
        XCTAssertEqual(e.name, "Prod box")
        XCTAssertEqual(e.hostname, "prod.example.com")
        XCTAssertEqual(e.port, 2200)
        XCTAssertEqual(e.username, "admin")
        XCTAssertEqual(e.password, "p,a\"ss word ")
        XCTAssertEqual(e.notes, "line one\r\nline two")
    }

    func testOnePasswordCSV() throws {
        let entries = try CredentialImporter.parseCSV("""
        Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
        Jump host,jump.example.com:2201,ops,"  leading and trailing  ",,false,false,,
        """)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].name, "Jump host")
        XCTAssertEqual(entries[0].hostname, "jump.example.com")
        XCTAssertEqual(entries[0].port, 2201)
        XCTAssertEqual(entries[0].password, "  leading and trailing  ")
    }

    func testLastPassCSV() throws {
        let entries = try CredentialImporter.parseCSV("""
        url,username,password,totp,extra,name,grouping,fav
        https://nas.local:5001/login,me,"pw""with""quotes",,some notes,NAS,Home,0
        http://sn,,,,Secure note body,My note,Notes,0
        """)
        XCTAssertEqual(entries.count, 1, "LastPass secure notes (http://sn) are skipped")
        XCTAssertEqual(entries[0].name, "NAS")
        XCTAssertEqual(entries[0].hostname, "nas.local")
        XCTAssertEqual(entries[0].port, 5001)
        XCTAssertEqual(entries[0].password, "pw\"with\"quotes")
        XCTAssertEqual(entries[0].notes, "some notes")
    }

    func testChromeCSV() throws {
        let entries = try CredentialImporter.parseCSV("""
        name,url,username,password,note
        router,https://192.168.1.1/,admin,hunter2,
        """)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].name, "router")
        XCTAssertEqual(entries[0].hostname, "192.168.1.1")
        XCTAssertEqual(entries[0].port, 22)
        XCTAssertEqual(entries[0].username, "admin")
    }

    func testFirefoxCSVWithoutNameUsesHost() throws {
        let entries = try CredentialImporter.parseCSV("""
        "url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
        "https://git.example.com","dev","pw","","https://git.example.com","{abc}","1","2","3"
        """)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].name, "git.example.com")
        XCTAssertEqual(entries[0].hostname, "git.example.com")
    }

    func testExplicitPortColumnBeatsURLPort() throws {
        let entries = try CredentialImporter.parseCSV("""
        name,url,port,username,password
        x,ssh://host.example.com:2200,2300,u,p
        y,ssh://host.example.com:2200,notaport,u,p
        """)
        XCTAssertEqual(entries.map(\.port), [2300, 2200])
    }

    func testUserFromURLWhenUsernameColumnEmpty() throws {
        let entries = try CredentialImporter.parseCSV("""
        name,url,username,password
        x,ssh://root@host.example.com,,p
        """)
        XCTAssertEqual(entries.first?.username, "root")
    }

    func testPasswordBytesAreNeverAltered() throws {
        let passwords = [
            " spaced ",
            "\"quoted\"",
            "comma,inside",
            "multi\nline\r\npassword",
            "tab\there",
            "unicode-\u{1F511}-e\u{301}",
            "back\\slash",
        ]
        var csv = "name,hostname,username,password\r\n"
        for (i, pw) in passwords.enumerated() {
            csv += "h\(i),host\(i).example.com,u,\"\(pw.replacingOccurrences(of: "\"", with: "\"\""))\"\r\n"
        }
        let entries = try CredentialImporter.parseCSV(csv)
        XCTAssertEqual(entries.count, passwords.count)
        for (entry, expected) in zip(entries, passwords) {
            XCTAssertEqual(Array(entry.password.utf8), Array(expected.utf8))
        }
    }

    func testRowsWithoutHostAreSkipped() throws {
        let entries = try CredentialImporter.parseCSV("""
        name,url,username,password
        nohost,,u,p
        bad,"has space",u,p

        ok,ok.example.com,u,p
        """)
        XCTAssertEqual(entries.map(\.hostname), ["ok.example.com"])
    }

    func testRecognisedHeaderWithoutHostColumnThrows() {
        XCTAssertThrowsError(try CredentialImporter.parseCSV("name,username,password\nx,u,p\n")) { error in
            XCTAssertEqual(error as? CredentialImporter.ImportError, .missingHostColumn)
        }
    }

    func testBOMHeaderIsRecognised() throws {
        let entries = try CredentialImporter.parse("\u{FEFF}name,url,username,password\nx,a.example.com,u,p\n", fileExtension: "csv")
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].name, "x")
    }

    func testUnterminatedQuoteIsReported() {
        XCTAssertThrowsError(try CredentialImporter.parseCSV("name,hostname,password\nx,h,\"open\n"))
    }

    // MARK: Bitwarden JSON

    func testBitwardenJSON() throws {
        let json = """
        {
          "encrypted": false,
          "items": [
            { "type": 1, "name": "Prod", "notes": "n",
              "login": { "username": "admin", "password": " pw with spaces\\n",
                         "uris": [ { "uri": "androidapp://x y" }, { "uri": "prod.example.com:2200" } ] } },
            { "type": 1, "name": "", "login": { "username": "", "password": "x",
                         "uris": [ { "uri": "ssh://deploy@[2001:db8::1]:2022" } ] } },
            { "type": 1, "name": "No URI", "login": { "username": "u", "password": "p" } },
            { "type": 2, "name": "Secure note", "notes": "secret" }
          ]
        }
        """
        let entries = try CredentialImporter.parse(json, fileExtension: "json")
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries[0].name, "Prod")
        XCTAssertEqual(entries[0].hostname, "prod.example.com")
        XCTAssertEqual(entries[0].port, 2200)
        XCTAssertEqual(entries[0].password, " pw with spaces\n")
        XCTAssertEqual(entries[0].notes, "n")
        XCTAssertEqual(entries[1].name, "2001:db8::1")
        XCTAssertEqual(entries[1].hostname, "2001:db8::1")
        XCTAssertEqual(entries[1].port, 2022)
        XCTAssertEqual(entries[1].username, "deploy")
    }

    func testJSONDetectedWithoutExtension() throws {
        let json = #"{"items":[{"type":1,"name":"A","login":{"uris":[{"uri":"a.example.com"}]}}]}"#
        XCTAssertEqual(try CredentialImporter.parse(json, fileExtension: "txt").count, 1)
    }

    func testEncryptedBitwardenExport() {
        let json = #"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "x", "data": "y"}"#
        XCTAssertThrowsError(try CredentialImporter.parse(json, fileExtension: "json")) { error in
            XCTAssertEqual(error as? CredentialImporter.ImportError, .encryptedExport)
        }
    }

    func testInvalidJSON() {
        XCTAssertThrowsError(try CredentialImporter.parse("{not json", fileExtension: "json")) { error in
            XCTAssertEqual(error as? CredentialImporter.ImportError, .invalidFormat)
        }
    }

    // MARK: Host addresses

    func testHostAddressParsing() {
        func p(_ s: String) -> HostAddress? { HostAddress.parse(s) }
        XCTAssertEqual(p("example.com"), HostAddress(host: "example.com", port: nil, user: nil))
        XCTAssertEqual(p("example.com:2222"), HostAddress(host: "example.com", port: 2222, user: nil))
        XCTAssertEqual(p("user@example.com"), HostAddress(host: "example.com", port: nil, user: "user"))
        XCTAssertEqual(p("ssh://user:pw@example.com:22/path?q#f"), HostAddress(host: "example.com", port: 22, user: "user"))
        XCTAssertEqual(p("https://example.com/login"), HostAddress(host: "example.com", port: nil, user: nil))
        XCTAssertEqual(p("[::1]:2200"), HostAddress(host: "::1", port: 2200, user: nil))
        XCTAssertEqual(p("fe80::1"), HostAddress(host: "fe80::1", port: nil, user: nil))
        XCTAssertEqual(p("192.168.1.10:99999"), HostAddress(host: "192.168.1.10", port: nil, user: nil))
        XCTAssertEqual(p("  padded.example.com  "), HostAddress(host: "padded.example.com", port: nil, user: nil))
        XCTAssertNil(p(""))
        XCTAssertNil(p("https://"))
        XCTAssertNil(p("two words"))
        XCTAssertNil(p("[::1"))
    }
}
