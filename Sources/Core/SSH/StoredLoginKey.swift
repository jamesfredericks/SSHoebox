import Foundation
import Citadel
import Crypto
import NIOCore
import NIOSSH

/// A stored ECDSA key (NIST P-256, P-384 or P-521), read from OpenSSH (encrypted or not),
/// SEC1 (`BEGIN EC PRIVATE KEY`) or PKCS#8 (`BEGIN PRIVATE KEY`) form.
public struct ECDSALoginKey: @unchecked Sendable {
    public enum Format: String, Sendable {
        case openSSH = "OpenSSH"
        case sec1 = "SEC1"
        case pkcs8 = "PKCS#8"
    }

    public let format: Format
    /// `ecdsa-sha2-nistp256` and so on: both the key type and the login algorithm.
    public let algorithm: String
    let privateKey: NIOSSHPrivateKey

    public var fingerprint: String { sshFingerprint(for: privateKey.publicKey) }

    /// Reads `pem` if it's an ECDSA key. Returns nil for other key types, and for an
    /// encrypted OpenSSH key without the right passphrase (the caller tells those apart).
    /// Throws for an ECDSA key in a form that can't be read here, with how to convert it.
    public static func parse(pem: String, decryptionKey: Data? = nil) throws -> ECDSALoginKey? {
        let pem = SSHKeyParser.normalizedPEM(pem)
        if pem.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            return try parseOpenSSH(pem, decryptionKey: decryptionKey)
        }
        let format: Format
        if pem.contains("-----BEGIN EC PRIVATE KEY-----") {
            if pem.contains("Proc-Type: 4,ENCRYPTED") { throw RSALoginKey.ParseError.legacyEncryption }
            format = .sec1
        } else if pem.contains("-----BEGIN PRIVATE KEY-----") {
            format = .pkcs8
        } else {
            return nil
        }
        if let key = try? P256.Signing.PrivateKey(pemRepresentation: pem) {
            return ECDSALoginKey(format: format, algorithm: "ecdsa-sha2-nistp256", privateKey: NIOSSHPrivateKey(p256Key: key))
        }
        if let key = try? P384.Signing.PrivateKey(pemRepresentation: pem) {
            return ECDSALoginKey(format: format, algorithm: "ecdsa-sha2-nistp384", privateKey: NIOSSHPrivateKey(p384Key: key))
        }
        if let key = try? P521.Signing.PrivateKey(pemRepresentation: pem) {
            return ECDSALoginKey(format: format, algorithm: "ecdsa-sha2-nistp521", privateKey: NIOSSHPrivateKey(p521Key: key))
        }
        if format == .sec1 { return try parseSEC1(pem) }
        return nil
    }

    /// SEC1 `ECPrivateKey` read by hand: macOS's `ssh-keygen -m PEM` writes the curve as
    /// explicit parameters rather than a named-curve OID, which CryptoKit doesn't accept.
    /// The curve follows from the size of the public point (or else the private value), and
    /// the public point is checked against the one derived from the private value.
    private static func parseSEC1(_ pem: String) throws -> ECDSALoginKey {
        let base64 = pem.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("-----") && !$0.contains(":") }.joined()
        guard let der = Data(base64Encoded: base64) else { throw RSALoginKey.ParseError.malformed("bad base64") }
        var outer = DERReader(Array(der))
        var fields = try outer.readSequence()
        guard try fields.read(DERReader.integer) == [1] else {
            throw RSALoginKey.ParseError.malformed("unknown EC private key version")
        }
        var scalar = try fields.read(DERReader.octetString)
        var publicPoint: [UInt8]?
        while !fields.isAtEnd {
            var (tag, contents) = try fields.readElement()
            if tag == 0xA1 {
                let bits = try contents.read(0x03) // BIT STRING: unused-bit count, then the point
                publicPoint = Array(bits.dropFirst())
            }
        }
        while scalar.first == 0, scalar.count > 32 { scalar.removeFirst() }
        let size: Int
        switch publicPoint?.count {
        case 65: size = 32
        case 97: size = 48
        case 133: size = 66
        default: size = scalar.count <= 32 ? 32 : scalar.count <= 48 ? 48 : 66
        }
        guard scalar.count <= size else { throw RSALoginKey.ParseError.malformed("EC private value too long") }
        let raw = Data(repeating: 0, count: size - scalar.count) + Data(scalar)
        let key: NIOSSHPrivateKey
        let derived: Data
        let algorithm: String
        do {
            switch size {
            case 32:
                let k = try P256.Signing.PrivateKey(rawRepresentation: raw)
                (key, derived, algorithm) = (NIOSSHPrivateKey(p256Key: k), k.publicKey.x963Representation, "ecdsa-sha2-nistp256")
            case 48:
                let k = try P384.Signing.PrivateKey(rawRepresentation: raw)
                (key, derived, algorithm) = (NIOSSHPrivateKey(p384Key: k), k.publicKey.x963Representation, "ecdsa-sha2-nistp384")
            default:
                let k = try P521.Signing.PrivateKey(rawRepresentation: raw)
                (key, derived, algorithm) = (NIOSSHPrivateKey(p521Key: k), k.publicKey.x963Representation, "ecdsa-sha2-nistp521")
            }
        } catch {
            throw RSALoginKey.ParseError.malformed("the EC private value is invalid")
        }
        if let publicPoint, Data(publicPoint) != derived {
            throw RSALoginKey.ParseError.malformed("the EC key's curve isn't P-256, P-384 or P-521")
        }
        return ECDSALoginKey(format: .sec1, algorithm: algorithm, privateKey: key)
    }

    private static func parseOpenSSH(_ pem: String, decryptionKey: Data?) throws -> ECDSALoginKey? {
        let fields: OpenSSHPrivateKeyFields
        do {
            fields = try OpenSSHPrivateKeyFields(openSSHKey: pem, decryptionKey: decryptionKey)
        } catch {
            return nil
        }
        guard fields.keyType.hasPrefix("ecdsa-sha2-") else { return nil }
        var buffer = fields.fields
        func readString() -> [UInt8]? {
            guard let length = buffer.readInteger(as: UInt32.self) else { return nil }
            return buffer.readBytes(length: Int(length))
        }
        guard let curveBytes = readString(), let curve = String(bytes: curveBytes, encoding: .utf8),
              readString() != nil, // public point Q, derived again from d
              var scalar = readString() else {
            throw RSALoginKey.ParseError.malformed("the OpenSSH ECDSA key is incomplete")
        }
        // An mpint may carry a leading zero byte, or be shorter than the curve's size.
        func scalarBytes(_ size: Int) -> Data {
            while scalar.count > size, scalar.first == 0 { scalar.removeFirst() }
            return Data(repeating: 0, count: max(0, size - scalar.count)) + Data(scalar)
        }
        let algorithm = "ecdsa-sha2-" + curve
        do {
            switch curve {
            case "nistp256":
                let key = try P256.Signing.PrivateKey(rawRepresentation: scalarBytes(32))
                return ECDSALoginKey(format: .openSSH, algorithm: algorithm, privateKey: NIOSSHPrivateKey(p256Key: key))
            case "nistp384":
                let key = try P384.Signing.PrivateKey(rawRepresentation: scalarBytes(48))
                return ECDSALoginKey(format: .openSSH, algorithm: algorithm, privateKey: NIOSSHPrivateKey(p384Key: key))
            case "nistp521":
                let key = try P521.Signing.PrivateKey(rawRepresentation: scalarBytes(66))
                return ECDSALoginKey(format: .openSSH, algorithm: algorithm, privateKey: NIOSSHPrivateKey(p521Key: key))
            default:
                throw RSALoginKey.ParseError.malformed("unsupported ECDSA curve \(curve)")
            }
        } catch let error as RSALoginKey.ParseError {
            throw error
        } catch {
            throw RSALoginKey.ParseError.malformed("the OpenSSH ECDSA key's private value is invalid")
        }
    }

    var loginAttempts: [PublicKeyAuthenticator.Attempt] {
        [.init(algorithm: algorithm, privateKey: privateKey)]
    }
}

/// A stored private key, read and ready to log in with.
enum StoredLoginKey {
    case ed25519(Curve25519.Signing.PrivateKey)
    case rsa(RSALoginKey)
    case ecdsa(ECDSALoginKey)

    enum Reading {
        case key(StoredLoginKey)
        /// Encrypted, and no passphrase was given.
        case needsPassphrase
        /// Encrypted, and the passphrase given doesn't open it (or it's no supported type).
        case wrongPassphrase
        /// A key of a type that can't log in directly. The detail names it for the log.
        case unsupported(String)
        /// A supported type in a form that can't be read; the error says how to convert it.
        case invalid(Error)
    }

    static func read(pem rawPEM: String, passphrase: String?) -> Reading {
        let pem = SSHKeyParser.normalizedPEM(rawPEM)
        let decryptionKey = passphrase.flatMap { $0.data(using: .utf8) }
        if let key = try? Curve25519.Signing.PrivateKey(sshEd25519: pem, decryptionKey: decryptionKey) {
            return .key(.ed25519(key))
        }
        do {
            if let key = try RSALoginKey.parse(pem: pem, decryptionKey: decryptionKey) { return .key(.rsa(key)) }
            if let key = try ECDSALoginKey.parse(pem: pem, decryptionKey: decryptionKey) { return .key(.ecdsa(key)) }
        } catch {
            return .invalid(error)
        }
        if SSHKeyParser.isEncryptedKey(pem) {
            return passphrase == nil ? .needsPassphrase : .wrongPassphrase
        }
        let fingerprint = (try? SSHKeyParser.publicKeyBlob(fromPEM: pem)).map(sshFingerprint(forBlob:))
        return .unsupported("not an Ed25519, ECDSA or RSA key" + (fingerprint.map { " (\($0))" } ?? ""))
    }

    /// What the login log says about the key.
    var summary: String {
        switch self {
        case .ed25519(let key):
            return "ssh-ed25519 \(sshFingerprint(for: NIOSSHPrivateKey(ed25519Key: key).publicKey))"
        case .rsa(let key):
            return "ssh-rsa \(key.bits)-bit \(key.format.rawValue) key \(sshFingerprint(forBlob: key.publicKeyBlob)); "
                + "logs in as \(RSALoginKey.algorithms.joined(separator: ", then ")) (never SHA-1 ssh-rsa)"
        case .ecdsa(let key):
            return "\(key.algorithm) \(key.format.rawValue) key \(key.fingerprint)"
        }
    }

    func authenticationMethod(username: String, trace: LoginTrace) -> SSHAuthenticationMethod {
        switch self {
        case .ed25519(let key):
            return .ed25519(username: username, privateKey: key)
        case .rsa(let key):
            return .custom(PublicKeyAuthenticator(username: username, attempts: key.loginAttempts, trace: trace))
        case .ecdsa(let key):
            return .custom(PublicKeyAuthenticator(username: username, attempts: key.loginAttempts, trace: trace))
        }
    }
}
