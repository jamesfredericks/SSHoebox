import Foundation
import NIOCore
import NIOSSH
import Crypto
import Citadel

/// A stored RSA private key, used for public-key login with `rsa-sha2-512` or `rsa-sha2-256`
/// (RFC 8332). It never logs in with SHA-1 `ssh-rsa`, which OpenSSH 8.8 and later refuse by
/// default.
///
/// Reads the three formats RSA keys are usually kept in:
/// - OpenSSH (`BEGIN OPENSSH PRIVATE KEY`), encrypted or not: what `ssh-keygen` writes today.
/// - PKCS#1 (`BEGIN RSA PRIVATE KEY`): older `ssh-keygen` and OpenSSL. Not when encrypted
///   (a `Proc-Type: 4,ENCRYPTED` header), which is an obsolete MD5-based scheme.
/// - PKCS#8 (`BEGIN PRIVATE KEY`), unencrypted.
public struct RSALoginKey: @unchecked Sendable {
    public enum Format: String, Sendable {
        case openSSH = "OpenSSH"
        case pkcs1 = "PKCS#1"
        case pkcs8 = "PKCS#8"
    }

    /// The login algorithms tried, in order. Servers that take RSA keys at all take
    /// `rsa-sha2-512`, except some embedded ones (Dropbear) that only take `rsa-sha2-256`.
    public static let algorithms = [RSASHA2_512.name, RSASHA2_256.name]

    public enum ParseError: Error, LocalizedError, Equatable {
        /// PKCS#1 with a `Proc-Type: 4,ENCRYPTED` header.
        case legacyEncryption
        /// `BEGIN ENCRYPTED PRIVATE KEY`.
        case encryptedPKCS8
        case malformed(String)

        public var errorDescription: String? {
            switch self {
            case .legacyEncryption:
                return "This RSA key is encrypted in the old OpenSSL format, which SSHoebox can't read. "
                    + "Convert it to the OpenSSH format with “ssh-keygen -p -f <key file>”, then paste it again."
            case .encryptedPKCS8:
                return "This key is an encrypted PKCS#8 key, which SSHoebox can't read. "
                    + "Convert it to the OpenSSH format with “ssh-keygen -p -f <key file>”, then paste it again."
            case .malformed(let detail):
                return "This RSA key couldn't be read (\(detail))."
            }
        }
    }

    private let key: Insecure.RSA.PrivateKey
    public let format: Format
    /// The SSH wire-format public key: `string "ssh-rsa"`, `mpint e`, `mpint n`.
    public let publicKeyBlob: Data
    /// The modulus size, such as 2048 or 4096.
    public let bits: Int

    private init(key: Insecure.RSA.PrivateKey, format: Format) throws {
        guard let publicKey = key.publicKey as? Insecure.RSA.PublicKey else {
            throw ParseError.malformed("no public key")
        }
        self.key = key
        self.format = format
        var blob = Data()
        Self.appendSSHString(Data("ssh-rsa".utf8), to: &blob)
        blob.append(publicKey.rawRepresentation)  // mpint e + mpint n
        self.publicKeyBlob = blob
        self.bits = try Self.modulusBits(ofPublicKey: publicKey.rawRepresentation)
    }

    /// The key in `pem`, or nil if `pem` isn't an RSA key in one of the formats above (or is
    /// an encrypted OpenSSH key and `decryptionKey` is missing or wrong).
    ///
    /// - Throws: `ParseError` for an RSA key in a format that can't be read, so the user is
    ///   told why rather than having the key silently skipped.
    public static func parse(pem: String, decryptionKey: Data? = nil) throws -> RSALoginKey? {
        let pem = SSHKeyParser.normalizedPEM(pem)
        let lines = pem.split(separator: "\n").map(String.init)
        guard let armor = lines.first else { return nil }

        switch armor {
        case "-----BEGIN OPENSSH PRIVATE KEY-----":
            guard let key = try? Insecure.RSA.PrivateKey(sshRsa: pem, decryptionKey: decryptionKey) else { return nil }
            return try RSALoginKey(key: key, format: .openSSH)

        case "-----BEGIN RSA PRIVATE KEY-----":
            if lines.contains(where: { $0.hasPrefix("Proc-Type:") && $0.contains("ENCRYPTED") }) {
                throw ParseError.legacyEncryption
            }
            let der = try body(of: lines)
            return try RSALoginKey(key: pkcs1PrivateKey(der), format: .pkcs1)

        case "-----BEGIN PRIVATE KEY-----":
            var reader = DERReader(try body(of: lines))
            var info = try reader.readSequence()
            _ = try info.read(DERReader.integer)  // version
            var algorithm = try info.readSequence()
            guard try algorithm.read(DERReader.objectIdentifier) == rsaEncryptionOID else {
                return nil  // an EC or Ed25519 key
            }
            return try RSALoginKey(key: pkcs1PrivateKey(info.read(DERReader.octetString)), format: .pkcs8)

        case "-----BEGIN ENCRYPTED PRIVATE KEY-----":
            throw ParseError.encryptedPKCS8

        default:
            return nil
        }
    }

    /// The key once for each of `algorithms`, for `PublicKeyAuthenticator` to offer in turn.
    var loginAttempts: [PublicKeyAuthenticator.Attempt] {
        let publicKeyData = publicKeyBlob.dropFirst(4 + "ssh-rsa".utf8.count)  // after the type string
        return [
            .init(algorithm: RSASHA2_512.name, privateKey: NIOSSHPrivateKey(custom:
                RSALoginPrivateKey<RSASHA2_512>(key: key, publicKeyData: Data(publicKeyData)))),
            .init(algorithm: RSASHA2_256.name, privateKey: NIOSSHPrivateKey(custom:
                RSALoginPrivateKey<RSASHA2_256>(key: key, publicKeyData: Data(publicKeyData)))),
        ]
    }

    // MARK: - Parsing

    /// 1.2.840.113549.1.1.1
    private static let rsaEncryptionOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

    /// The DER bytes between the armor lines.
    private static func body(of lines: [String]) throws -> [UInt8] {
        let base64 = lines.filter { !$0.hasPrefix("-----") && !$0.contains(":") }.joined()
        guard let der = Data(base64Encoded: base64), !der.isEmpty else {
            throw ParseError.malformed("invalid base64")
        }
        return Array(der)
    }

    /// RFC 8017 A.1.2: `RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }`.
    private static func pkcs1PrivateKey(_ der: [UInt8]) throws -> Insecure.RSA.PrivateKey {
        var reader = DERReader(der)
        var fields = try reader.readSequence()
        guard try fields.read(DERReader.integer) == [0] else {
            throw ParseError.malformed("unsupported version (multi-prime key?)")
        }
        let modulus = try fields.read(DERReader.integer)
        let publicExponent = try fields.read(DERReader.integer)
        let privateExponent = try fields.read(DERReader.integer)
        guard modulus.contains(where: { $0 != 0 }), privateExponent.contains(where: { $0 != 0 }) else {
            throw ParseError.malformed("zero modulus or exponent")
        }
        return Insecure.RSA.PrivateKey(modulus: modulus, publicExponent: publicExponent, privateExponent: privateExponent)
    }

    /// The bit length of `n` in `mpint e + mpint n`.
    private static func modulusBits(ofPublicKey data: Data) throws -> Int {
        var bytes = Array(data)[...]
        func readMPInt() throws -> ArraySlice<UInt8> {
            guard bytes.count >= 4 else { throw ParseError.malformed("short public key") }
            let length = bytes.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            bytes = bytes.dropFirst(4)
            guard bytes.count >= length else { throw ParseError.malformed("short public key") }
            defer { bytes = bytes.dropFirst(length) }
            return bytes.prefix(length)
        }
        _ = try readMPInt()
        let modulus = try readMPInt().drop(while: { $0 == 0 })
        guard let first = modulus.first else { throw ParseError.malformed("zero modulus") }
        return (modulus.count - 1) * 8 + (8 - first.leadingZeroBitCount)
    }

    private static func appendSSHString(_ bytes: Data, to data: inout Data) {
        var length = UInt32(bytes.count).bigEndian
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(bytes)
    }
}

/// Just enough DER to read PKCS#1 and PKCS#8 RSA private keys.
private struct DERReader {
    static let integer: UInt8 = 0x02
    static let octetString: UInt8 = 0x04
    static let objectIdentifier: UInt8 = 0x06
    static let sequence: UInt8 = 0x30

    private var bytes: ArraySlice<UInt8>

    init(_ bytes: [UInt8]) { self.bytes = bytes[...] }
    private init(slice: ArraySlice<UInt8>) { self.bytes = slice }

    /// The contents of the next element, which must have `tag`.
    mutating func read(_ tag: UInt8) throws -> [UInt8] {
        Array(try readSlice(tag))
    }

    /// The next element, which must be a SEQUENCE, as a reader over its contents.
    mutating func readSequence() throws -> DERReader {
        DERReader(slice: try readSlice(Self.sequence))
    }

    private mutating func readSlice(_ tag: UInt8) throws -> ArraySlice<UInt8> {
        guard let actual = bytes.popFirst(), actual == tag else {
            throw RSALoginKey.ParseError.malformed("unexpected DER structure")
        }
        guard let first = bytes.popFirst() else { throw RSALoginKey.ParseError.malformed("truncated DER") }
        var length = Int(first)
        if first & 0x80 != 0 {
            let count = Int(first & 0x7F)
            guard (1...4).contains(count), bytes.count >= count else {
                throw RSALoginKey.ParseError.malformed("bad DER length")
            }
            length = bytes.prefix(count).reduce(0) { $0 << 8 | Int($1) }
            bytes = bytes.dropFirst(count)
        }
        guard bytes.count >= length else { throw RSALoginKey.ParseError.malformed("truncated DER") }
        defer { bytes = bytes.dropFirst(length) }
        return bytes.prefix(length)
    }
}

// MARK: - NIOSSH key types

protocol RSALoginAlgorithm {
    static var name: String { get }
    static func sign(_ data: Data, with key: Insecure.RSA.PrivateKey) throws -> Data
}

enum RSASHA2_512: RSALoginAlgorithm {
    static let name = "rsa-sha2-512"
    static func sign(_ data: Data, with key: Insecure.RSA.PrivateKey) throws -> Data {
        try key.signatureSHA512(for: data).rawRepresentation
    }
}

enum RSASHA2_256: RSALoginAlgorithm {
    static let name = "rsa-sha2-256"
    static func sign(_ data: Data, with key: Insecure.RSA.PrivateKey) throws -> Data {
        try key.signatureSHA256(for: data).rawRepresentation
    }
}

/// An RSA key that signs logins with `Algorithm`. The key blob still says `ssh-rsa`; the
/// login request and the signature say `Algorithm.name`.
struct RSALoginPrivateKey<Algorithm: RSALoginAlgorithm>: NIOSSHPrivateKeyProtocol {
    static var keyPrefix: String { "ssh-rsa" }

    let key: Insecure.RSA.PrivateKey
    /// `mpint e + mpint n`.
    let publicKeyData: Data

    var publicKey: NIOSSHPublicKeyProtocol {
        RSALoginPublicKey<Algorithm>(rawRepresentation: publicKeyData)
    }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        RSALoginSignature<Algorithm>(rawRepresentation: try Algorithm.sign(Data(data), with: key))
    }
}

struct RSALoginPublicKey<Algorithm: RSALoginAlgorithm>: NIOSSHUserAuthAlgorithmNaming {
    static var publicKeyPrefix: String { "ssh-rsa" }
    var userAuthAlgorithmName: String { Algorithm.name }

    let rawRepresentation: Data

    /// Only servers verify signatures, and a client never acts as one for its own key.
    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        false
    }

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeBytes(rawRepresentation)
    }

    /// Not used: these keys are only ever sent, never parsed from the wire.
    static func read(from buffer: inout ByteBuffer) throws -> RSALoginPublicKey<Algorithm> {
        throw RSALoginKey.ParseError.malformed("not readable")
    }
}

/// An RSA PKCS#1 v1.5 signature, sent as `string Algorithm.name`, `string signature`.
struct RSALoginSignature<Algorithm: RSALoginAlgorithm>: NIOSSHSignatureProtocol {
    static var signaturePrefix: String { Algorithm.name }

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeInteger(UInt32(rawRepresentation.count)) + buffer.writeBytes(rawRepresentation)
    }

    /// Not used: these signatures are only ever sent, never parsed from the wire.
    static func read(from buffer: inout ByteBuffer) throws -> RSALoginSignature<Algorithm> {
        throw RSALoginKey.ParseError.malformed("not readable")
    }
}
