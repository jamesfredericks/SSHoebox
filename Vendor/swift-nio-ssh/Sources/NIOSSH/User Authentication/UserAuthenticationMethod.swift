//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIOCore

/// The user authentication modes available at this point in time.
public struct NIOSSHAvailableUserAuthenticationMethods: OptionSet {
    public var rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let publicKey: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 0)
    public static let password: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 1)
    public static let hostBased: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 2)
    /// Keyboard-interactive (RFC 4256). Only clients support it, so it is not part of `all`.
    public static let keyboardInteractive: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 3)

    public static let all: NIOSSHAvailableUserAuthenticationMethods = [.publicKey, .password, .hostBased]
}

extension NIOSSHAvailableUserAuthenticationMethods {
    internal init(_ message: SSHMessage.UserAuthFailureMessage) {
        self = .init()

        for message in message.authentications {
            switch message {
            case "publickey":
                self.insert(.publicKey)
            case "password":
                self.insert(.password)
            case "hostbased":
                self.insert(.hostBased)
            case "keyboard-interactive":
                self.insert(.keyboardInteractive)
            default:
                // This is an unknown method, which we ignore.
                break
            }
        }
    }

    internal var strings: [Substring] {
        guard self != .init() else {
            return []
        }

        // We need an array.
        var methods = [Substring]()
        methods.reserveCapacity(4)

        if self.contains(.password) {
            methods.append("password")
        }
        if self.contains(.publicKey) {
            methods.append("publickey")
        }
        if self.contains(.hostBased) {
            methods.append("hostbased")
        }
        if self.contains(.keyboardInteractive) {
            methods.append("keyboard-interactive")
        }

        return methods
    }
}

extension NIOSSHAvailableUserAuthenticationMethods: Hashable {}

/// A specific request for user authentication. This type is the one observed from the server side. The
/// associated client side type is `NIOSSHUserAuthenticationOffer`.
public struct NIOSSHUserAuthenticationRequest {
    public var username: String

    public var request: Request

    public init(username: String, serviceName: String, request: Request) {
        self.username = username
        self.request = request
    }
}

public extension NIOSSHUserAuthenticationRequest {
    enum Request {
        case publicKey(PublicKey)
        case password(Password)
        case hostBased(HostBased)
        case none
    }
}

public extension NIOSSHUserAuthenticationRequest.Request {
    struct PublicKey {
        public var publicKey: NIOSSHPublicKey

        public init(publicKey: NIOSSHPublicKey) {
            self.publicKey = publicKey
        }
    }

    struct Password {
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    struct HostBased {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}

extension NIOSSHUserAuthenticationRequest: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.PublicKey: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.Password: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.HostBased: Hashable {}

/// A specific offer of user authentication. This type is the one used on the client side. The
/// associated server side type is `NIOSSHUserAuthenticationRequest`.
public struct NIOSSHUserAuthenticationOffer {
    public var username: String

    public var offer: Offer

    public init(username: String, serviceName: String, offer: Offer) {
        self.username = username
        self.offer = offer
    }
}

public extension NIOSSHUserAuthenticationOffer {
    enum Offer {
        case privateKey(PrivateKey)
        case password(Password)
        case hostBased(HostBased)
        /// Keyboard-interactive (RFC 4256). The server's prompts are answered through
        /// ``NIOSSHClientUserAuthenticationDelegate/respondToKeyboardInteractiveChallenge(_:responsePromise:)``.
        case keyboardInteractive(KeyboardInteractive)
        case none
    }
}

public extension NIOSSHUserAuthenticationOffer.Offer {
    struct KeyboardInteractive {
        /// Comma-separated submethod hints for the server; usually empty.
        public var submethods: String

        public init(submethods: String = "") {
            self.submethods = submethods
        }
    }

    struct PrivateKey {
        public var privateKey: NIOSSHPrivateKey
        public var publicKey: NIOSSHPublicKey

        public init(privateKey: NIOSSHPrivateKey) {
            self.privateKey = privateKey
            self.publicKey = privateKey.publicKey
        }

        public init(privateKey: NIOSSHPrivateKey, certifiedKey: NIOSSHCertifiedPublicKey) {
            self.privateKey = privateKey
            self.publicKey = NIOSSHPublicKey(certifiedKey)
        }
    }

    struct Password {
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    struct HostBased {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}

extension SSHMessage.UserAuthRequestMessage {
    init(request: NIOSSHUserAuthenticationOffer, sessionID: ByteBuffer) throws {
        // We only ever ask for the ssh-connection service.
        self.username = request.username
        self.service = "ssh-connection"

        switch request.offer {
        case .privateKey(let privateKeyRequest):
            let dataToSign = UserAuthSignablePayload(
                sessionIdentifier: sessionID,
                userName: self.username,
                serviceName: self.service,
                publicKey: privateKeyRequest.publicKey
            )
            let signature = try privateKeyRequest.privateKey.sign(dataToSign)
            self.method = .publicKey(.known(key: privateKeyRequest.publicKey, signature: signature))
        case .password(let passwordRequest):
            self.method = .password(passwordRequest.password)
        case .hostBased:
            fatalError("Unsupported")
        case .keyboardInteractive(let keyboardInteractive):
            self.method = .keyboardInteractive(submethods: keyboardInteractive.submethods)
        case .none:
            self.method = .none
        }
    }
}

/// A round of keyboard-interactive prompts from the server (SSH_MSG_USERAUTH_INFO_REQUEST).
/// A round may have no prompts at all, in which case it must be answered with no responses.
public struct NIOSSHKeyboardInteractiveChallenge: Hashable, Sendable {
    public struct Prompt: Hashable, Sendable {
        /// The text to show, such as "Password: " or "Verification code: ".
        public var prompt: String

        /// Whether the answer may be shown as it is typed. False for secrets.
        public var echo: Bool

        public init(prompt: String, echo: Bool) {
            self.prompt = prompt
            self.echo = echo
        }
    }

    public var name: String
    public var instruction: String
    public var prompts: [Prompt]

    public init(name: String, instruction: String, prompts: [Prompt]) {
        self.name = name
        self.instruction = instruction
        self.prompts = prompts
    }
}

extension NIOSSHKeyboardInteractiveChallenge {
    init(_ message: SSHMessage.UserAuthInfoRequestMessage) {
        self.init(
            name: message.name,
            instruction: message.instruction,
            prompts: message.prompts.map { .init(prompt: $0.prompt, echo: $0.echo) }
        )
    }
}

/// The outcome of a user authentication attempt.
public enum NIOSSHUserAuthenticationOutcome {
    case success
    case partialSuccess(remainingMethods: NIOSSHAvailableUserAuthenticationMethods)
    case failure
}

enum NIOSSHUserAuthenticationResponseMessage {
    case success
    case failure(SSHMessage.UserAuthFailureMessage)
    case publicKeyOK(SSHMessage.UserAuthPKOKMessage)
}

extension NIOSSHUserAuthenticationResponseMessage {
    init(_ outcome: NIOSSHUserAuthenticationOutcome, supportedMethods: NIOSSHAvailableUserAuthenticationMethods) {
        switch outcome {
        case .success:
            self = .success
        case .partialSuccess(remainingMethods: let remaining):
            let message = SSHMessage.UserAuthFailureMessage(authentications: remaining.strings, partialSuccess: true)
            self = .failure(message)
        case .failure:
            let message = SSHMessage.UserAuthFailureMessage(authentications: supportedMethods.strings, partialSuccess: false)
            self = .failure(message)
        }
    }
}
