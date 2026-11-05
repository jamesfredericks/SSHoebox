import Foundation
import NIOCore
import NIOSSH

/// Logs in with one stored key, offered under each of its login algorithms in turn (for RSA:
/// `rsa-sha2-512`, then `rsa-sha2-256`). Like `KeyboardInteractiveAuthenticator`, it first
/// sends a `none` request to learn what the server accepts.
///
/// NIOSSH calls it on the connection's event loop, one call at a time.
final class PublicKeyAuthenticator: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    struct Attempt {
        let algorithm: String
        let privateKey: NIOSSHPrivateKey
    }

    private let username: String
    private let attempts: [Attempt]
    private let trace: LoginTrace
    private var probed = false
    private var next = 0

    init(username: String, attempts: [Attempt], trace: LoginTrace = LoginTrace()) {
        self.username = username
        self.attempts = attempts
        self.trace = trace
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        func offer(_ offer: NIOSSHUserAuthenticationOffer.Offer) {
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(
                username: username, serviceName: "ssh-connection", offer: offer))
        }

        guard probed else {
            probed = true
            trace.info("auth: sending 'none' to learn which methods the server accepts")
            offer(.none)
            return
        }

        let tried = attempts.prefix(next).map(\.algorithm)
        trace.info("auth: server accepts [\(LoginTrace.describe(availableMethods))]"
                   + (tried.isEmpty ? "" : " after rejecting the key as \(tried.last!)"))

        guard availableMethods.contains(.publicKey) else {
            if tried.isEmpty {
                trace.error("auth: the server doesn't accept public key login")
                nextChallengePromise.fail(SSHLoginError.noUsableMethod("public key"))
            } else {
                trace.error("auth: the server stopped accepting public key login")
                nextChallengePromise.fail(SSHLoginError.keyRejected)
            }
            return
        }

        guard next < attempts.count else {
            trace.error("auth: the server rejected the key as \(tried.joined(separator: " and ")). Is its "
                        + "public key in ~/.ssh/authorized_keys for \(LoginTrace.quoted(username))? "
                        + "The server log (journalctl -u ssh, /var/log/auth.log) gives the reason.")
            nextChallengePromise.fail(SSHLoginError.keyRejected)
            return
        }

        let attempt = attempts[next]
        next += 1
        trace.info("auth: offering the key as \(attempt.algorithm)")
        offer(.privateKey(.init(privateKey: attempt.privateKey)))
    }
}
