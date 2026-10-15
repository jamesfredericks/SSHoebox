import NIO
import NIOSSH
import Crypto

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
    }
    
    private let allImplementations: [Implementation]
    private var implementations: [Implementation]
    /// The implementation whose offer is in flight; it answers any keyboard-interactive prompts.
    private var currentImplementation: Implementation?
    
    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.allImplementations = [.user(username, offer: offer)]
        self.implementations = allImplementations
    }
    
    internal init(
        custom: NIOSSHClientUserAuthenticationDelegate
    ) {
        self.allImplementations = [.custom(custom)]
        self.implementations = allImplementations
    }
    
    /// Creates a password based authentication method.
    /// - Parameters:
    ///  - username: The username to authenticate with.
    /// - password: The password to authenticate with.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }
    
    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
    }
    
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // SSHoebox patch: a custom delegate may make several offers (probe with `none`, then
        // keyboard-interactive, ...) and fails the promise itself once it has run out.
        if case .custom(let implementation)? = currentImplementation {
            implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
            return
        }

        if implementations.isEmpty {
            nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
            return
        }
        
        let implementation = implementations.removeFirst()
        currentImplementation = implementation

        switch implementation {
        case .user(let username, offer: let offer):
            switch offer {
            case .password:
                guard availableMethods.contains(.password) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPasswordAuthentication)
                    return
                }
            case .hostBased:
                guard availableMethods.contains(.hostBased) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedHostBasedAuthentication)
                    return
                }
            case .privateKey:
                guard availableMethods.contains(.publicKey) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPrivateKeyAuthentication)
                    return
                }
            case .keyboardInteractive:
                // Not checked: the first round is offered before the server lists its methods,
                // and NIOSSH leaves keyboard-interactive out of the `.all` it starts with.
                ()
            case .none:
                ()
            }
            
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "ssh-connection", offer: offer))
        case .custom(let implementation):
            implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
        }
    }

    public func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        switch currentImplementation {
        case .custom(let implementation):
            implementation.respondToKeyboardInteractiveChallenge(challenge, responsePromise: responsePromise)
        case .user, .none:
            // A plain offer has nothing to answer prompts with.
            responsePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
        }
    }
}
