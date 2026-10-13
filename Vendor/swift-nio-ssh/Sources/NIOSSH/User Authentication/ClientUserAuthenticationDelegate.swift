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

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentictation methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>)

    /// Called when the server sends a round of prompts for a keyboard-interactive offer.
    ///
    /// The delegate completes `responsePromise` with one answer per prompt, in order. The server may send
    /// several rounds before it accepts or rejects the attempt. Failing the promise ends connection establishment.
    /// The default implementation fails it, so delegates that never offer keyboard-interactive need not implement this.
    ///
    /// - parameters:
    ///     - challenge: The prompts the server wants answered.
    ///     - responsePromise: An `EventLoopPromise` to be fulfilled with the answers.
    func respondToKeyboardInteractiveChallenge(_ challenge: NIOSSHKeyboardInteractiveChallenge, responsePromise: EventLoopPromise<[String]>)
}

extension NIOSSHClientUserAuthenticationDelegate {
    public func respondToKeyboardInteractiveChallenge(_ challenge: NIOSSHKeyboardInteractiveChallenge, responsePromise: EventLoopPromise<[String]>) {
        responsePromise.fail(NIOSSHError.protocolViolation(protocolName: "userauth", violation: "keyboard-interactive challenge received by a delegate that doesn't answer them"))
    }
}
