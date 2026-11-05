import XCTest
import Security
import NIOCore
import NIOPosix
@testable import NIOSSH
@testable import SSHoeboxCore

/// Stored RSA keys log in with rsa-sha2-512 / rsa-sha2-256 (RFC 8332), never SHA-1 ssh-rsa.
final class RSALoginKeyTests: XCTestCase {

    private func blob(ofPublicLine line: String) -> Data {
        Data(base64Encoded: String(line.split(separator: " ")[1]))!
    }

    // MARK: - Parsing

    func testReadsEveryUnencryptedFormat() throws {
        let cases: [(String, String, RSALoginKey.Format)] = [
            (TestKeys.rsa, TestKeys.rsaPublic, .openSSH),
            (TestKeys.rsaPKCS1, TestKeys.rsaPKCS1Public, .pkcs1),
            (TestKeys.rsaPKCS8, TestKeys.rsaPKCS8Public, .pkcs8),
        ]
        for (pem, publicLine, format) in cases {
            let key = try XCTUnwrap(try RSALoginKey.parse(pem: pem), "\(format)")
            XCTAssertEqual(key.format, format)
            XCTAssertEqual(key.bits, 2048, "\(format)")
            XCTAssertEqual(key.publicKeyBlob, blob(ofPublicLine: publicLine), "\(format): public key differs from ssh-keygen's")
        }
    }

    func testToleratesWindowsLineEndings() throws {
        let crlf = TestKeys.rsaPKCS1.replacingOccurrences(of: "\n", with: "\r\n")
        XCTAssertEqual(try RSALoginKey.parse(pem: crlf)?.publicKeyBlob, blob(ofPublicLine: TestKeys.rsaPKCS1Public))
    }

    func testEncryptedOpenSSHKeyNeedsItsPassphrase() throws {
        XCTAssertNil(try RSALoginKey.parse(pem: TestKeys.rsaEncrypted), "no passphrase")
        XCTAssertNil(try RSALoginKey.parse(pem: TestKeys.rsaEncrypted, decryptionKey: Data("wrong".utf8)))
        let key = try XCTUnwrap(try RSALoginKey.parse(pem: TestKeys.rsaEncrypted,
                                                      decryptionKey: Data(TestKeys.passphrase.utf8)))
        XCTAssertEqual(key.publicKeyBlob, blob(ofPublicLine: TestKeys.rsaEncryptedPublic))
    }

    func testOtherKeyTypesAreNotRSA() throws {
        XCTAssertNil(try RSALoginKey.parse(pem: TestKeys.ed25519))
        XCTAssertNil(try RSALoginKey.parse(pem: TestKeys.p256))
        XCTAssertNil(try RSALoginKey.parse(pem: TestKeys.ecPKCS8))
        XCTAssertNil(try RSALoginKey.parse(pem: "not a key"))
    }

    func testUnreadableRSAFormatsSayHowToConvert() {
        XCTAssertThrowsError(try RSALoginKey.parse(pem: TestKeys.rsaPKCS1LegacyEncrypted)) { error in
            XCTAssertEqual(error as? RSALoginKey.ParseError, .legacyEncryption)
            XCTAssertTrue(error.localizedDescription.contains("ssh-keygen -p -f"), error.localizedDescription)
        }
        XCTAssertThrowsError(try RSALoginKey.parse(pem: TestKeys.rsaPKCS8Encrypted)) { error in
            XCTAssertEqual(error as? RSALoginKey.ParseError, .encryptedPKCS8)
        }
        let truncated = TestKeys.rsaPKCS1.split(separator: "\n").prefix(5).joined(separator: "\n")
            + "\n-----END RSA PRIVATE KEY-----\n"
        XCTAssertThrowsError(try RSALoginKey.parse(pem: truncated))
    }

    // MARK: - Login request

    /// The publickey request names rsa-sha2-512, sends an ssh-rsa key blob, and carries an
    /// rsa-sha2-512 signature over the RFC 4252 payload that Apple's RSA implementation accepts.
    func testLoginRequestUsesSHA2AndVerifies() throws {
        let key = try XCTUnwrap(try RSALoginKey.parse(pem: TestKeys.rsaPKCS1))
        let verifier = try publicSecKey(fromPKCS1: TestKeys.rsaPKCS1)
        let sessionID = ByteBuffer(bytes: (0..<32).map { UInt8($0) })

        for (attempt, secAlgorithm) in zip(key.loginAttempts, [SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512,
                                                                .rsaSignatureMessagePKCS1v15SHA256]) {
            let offer = NIOSSHUserAuthenticationOffer(username: "admin", serviceName: "ssh-connection",
                                                      offer: .privateKey(.init(privateKey: attempt.privateKey)))
            let message = try SSHMessage.UserAuthRequestMessage(request: offer, sessionID: sessionID)
            var buffer = ByteBuffer()
            buffer.writeUserAuthRequestMessage(message)

            XCTAssertEqual(buffer.readSSHStringAsString(), "admin")
            XCTAssertEqual(buffer.readSSHStringAsString(), "ssh-connection")
            XCTAssertEqual(buffer.readSSHStringAsString(), "publickey")
            XCTAssertEqual(buffer.readSSHBoolean(), true)
            XCTAssertEqual(buffer.readSSHStringAsString(), attempt.algorithm, "public key algorithm name")
            var keyBlob = try XCTUnwrap(buffer.readSSHString())
            XCTAssertEqual(Data(keyBlob.readableBytesView), key.publicKeyBlob)
            XCTAssertEqual(keyBlob.readSSHStringAsString(), "ssh-rsa", "the key blob keeps its key type")
            var signatureBlob = try XCTUnwrap(buffer.readSSHString())
            XCTAssertEqual(buffer.readableBytes, 0)
            XCTAssertEqual(signatureBlob.readSSHStringAsString(), attempt.algorithm, "signature algorithm name")
            let signature = Data(try XCTUnwrap(signatureBlob.readSSHString()).readableBytesView)

            let payload = UserAuthSignablePayload(sessionIdentifier: sessionID, userName: "admin",
                                                  serviceName: "ssh-connection",
                                                  publicKey: attempt.privateKey.publicKey)
            var error: Unmanaged<CFError>?
            XCTAssertTrue(SecKeyVerifySignature(verifier, secAlgorithm, Data(payload.bytes.readableBytesView) as CFData,
                                                signature as CFData, &error),
                          "\(attempt.algorithm) signature doesn't verify: \(String(describing: error?.takeRetainedValue()))")

            XCTAssertEqual(SSHMessage.userAuthRequest(message).redactedDebugLines,
                           ["SSH_MSG_USERAUTH_REQUEST user \"admin\" service ssh-connection method "
                            + "publickey \(attempt.algorithm) (ssh-rsa key) with signature"])
        }
    }

    /// Ed25519 and other built-in keys still name the key type as the algorithm.
    func testOtherKeysAreUnchanged() throws {
        let key = NIOSSHPrivateKey(ed25519Key: .init())
        let offer = NIOSSHUserAuthenticationOffer(username: "u", serviceName: "ssh-connection",
                                                  offer: .privateKey(.init(privateKey: key)))
        let message = try SSHMessage.UserAuthRequestMessage(request: offer, sessionID: ByteBuffer(bytes: [1, 2, 3]))
        XCTAssertEqual(SSHMessage.userAuthRequest(message).redactedDebugLines,
                       ["SSH_MSG_USERAUTH_REQUEST user \"u\" service ssh-connection method publickey ssh-ed25519 with signature"])
    }

    // MARK: - Authenticator

    func testAuthenticatorTriesSHA512ThenSHA256ThenStops() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let lines = LoginTraceTests.CapturedLines()
        let key = try XCTUnwrap(try RSALoginKey.parse(pem: TestKeys.rsaPKCS1))
        let auth = PublicKeyAuthenticator(username: "admin", attempts: key.loginAttempts, trace: LoginTrace(sink: lines.sink))

        func next(_ methods: NIOSSHAvailableUserAuthenticationMethods) async throws -> NIOSSHUserAuthenticationOffer? {
            let promise = loop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
            loop.execute { auth.nextAuthenticationType(availableMethods: methods, nextChallengePromise: promise) }
            return try await promise.futureResult.get()
        }
        func algorithm(_ offer: NIOSSHUserAuthenticationOffer?) -> String? {
            guard case .privateKey(let request) = offer?.offer else { return nil }
            return String(request.publicKey.userAuthAlgorithmName)
        }

        guard case .some(.none) = try await next(.all)?.offer else { return XCTFail("probes with 'none' first") }
        let first = try await next(.publicKey)
        XCTAssertEqual(algorithm(first), "rsa-sha2-512")
        let second = try await next(.publicKey)
        XCTAssertEqual(algorithm(second), "rsa-sha2-256")
        do {
            _ = try await next(.publicKey)
            XCTFail("gives up after both algorithms")
        } catch {
            XCTAssertEqual((error as? SSHLoginError)?.description, SSHLoginError.keyRejected.description)
        }
        XCTAssertTrue(lines.errors.contains { $0.contains("rejected the key as rsa-sha2-512 and rsa-sha2-256") }, lines.text)
    }

    func testAuthenticatorReportsAServerWithoutPublicKeyLogin() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let key = try XCTUnwrap(try RSALoginKey.parse(pem: TestKeys.rsaPKCS1))
        let auth = PublicKeyAuthenticator(username: "admin", attempts: key.loginAttempts)
        for methods: NIOSSHAvailableUserAuthenticationMethods in [.all, .password] {
            let promise = loop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
            loop.execute { auth.nextAuthenticationType(availableMethods: methods, nextChallengePromise: promise) }
            if methods == .password {
                do {
                    _ = try await promise.futureResult.get()
                    XCTFail("should fail")
                } catch {
                    XCTAssertEqual((error as? SSHLoginError)?.description, "The server doesn't accept public key login.")
                }
            } else {
                _ = try await promise.futureResult.get()
            }
        }
    }

    // MARK: - Helpers

    private func publicSecKey(fromPKCS1 pem: String) throws -> SecKey {
        let base64 = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let der = try XCTUnwrap(Data(base64Encoded: base64))
        var error: Unmanaged<CFError>?
        let privateKey = try XCTUnwrap(SecKeyCreateWithData(der as CFData, [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ] as CFDictionary, &error), "\(String(describing: error?.takeRetainedValue()))")
        return try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
    }
}
