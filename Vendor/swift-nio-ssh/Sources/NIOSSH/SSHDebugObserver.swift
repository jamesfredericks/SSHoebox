//===----------------------------------------------------------------------===//
//
// SSHoebox patch: `ssh -v`-style protocol diagnostics.
//
//===----------------------------------------------------------------------===//

import NIOCore

/// Receives one line per protocol event when set on `SSHClientConfiguration.debugObserver`:
/// the TCP connection, each SSH message sent ("→") or received ("←"), and the negotiated
/// algorithms. Called on the connection's event loop, so it must not block.
///
/// The lines never contain secrets: passwords, keyboard-interactive answers, `env` values and
/// `exec` commands are left out, and channel data (terminal and SFTP traffic) is not reported
/// at all, nor are window adjustments and terminal resizes.
public typealias NIOSSHDebugObserver = @Sendable (String) -> Void

extension SSHConnectionRole {
    internal var debugObserver: NIOSSHDebugObserver? {
        switch self {
        case .client(let configuration):
            return configuration.debugObserver
        case .server:
            return nil
        }
    }
}

extension SSHMessage {
    /// What this message says, minus anything secret. Empty for messages that are never
    /// reported (channel data, window adjustments, terminal resizes).
    internal var redactedDebugLines: [String] {
        switch self {
        case .version(let version):
            return ["version \(quoted(version))"]
        case .disconnect(let message):
            return ["SSH_MSG_DISCONNECT reason \(message.reason) (\(disconnectReason(message.reason))) \(quoted(message.description))"]
        case .ignore(let message):
            return ["SSH_MSG_IGNORE (\(message.data.readableBytes) bytes)"]
        case .unimplemented(let message):
            return ["SSH_MSG_UNIMPLEMENTED for packet \(message.sequenceNumber)"]
        case .debug(let message):
            return ["SSH_MSG_DEBUG \(quoted(message.message))"]
        case .serviceRequest(let message):
            return ["SSH_MSG_SERVICE_REQUEST \(message.service)"]
        case .serviceAccept(let message):
            return ["SSH_MSG_SERVICE_ACCEPT \(message.service)"]
        case .keyExchange(let message):
            var lines = ["SSH_MSG_KEXINIT"]
            lines.append("  kex algorithms: \(list(message.keyExchangeAlgorithms))")
            lines.append("  host key algorithms: \(list(message.serverHostKeyAlgorithms))")
            lines.append(contentsOf: pair("ciphers", message.encryptionAlgorithmsClientToServer, message.encryptionAlgorithmsServerToClient))
            lines.append(contentsOf: pair("MACs", message.macAlgorithmsClientToServer, message.macAlgorithmsServerToClient))
            lines.append(contentsOf: pair("compression", message.compressionAlgorithmsClientToServer, message.compressionAlgorithmsServerToClient))
            if message.firstKexPacketFollows { lines.append("  first_kex_packet_follows") }
            return lines
        case .keyExchangeInit(let message):
            return ["SSH_MSG_KEX_ECDH_INIT (\(message.publicKey.readableBytes)-byte ephemeral key)"]
        case .keyExchangeReply(let message):
            return ["SSH_MSG_KEX_ECDH_REPLY host key \(String(message.hostKey.keyPrefix)), "
                + "\(message.publicKey.readableBytes)-byte ephemeral key, signed"]
        case .newKeys:
            return ["SSH_MSG_NEWKEYS"]
        case .userAuthRequest(let message):
            let method: String
            switch message.method {
            case .none:
                method = "none"
            case .password:
                method = "password (not logged)"
            case .publicKey(.known(let key, let signature)):
                let algorithm = String(key.userAuthAlgorithmName)
                let keyType = String(key.keyPrefix)
                method = "publickey \(algorithm)" + (algorithm == keyType ? "" : " (\(keyType) key)")
                    + " \(signature == nil ? "(query, no signature)" : "with signature")"
            case .publicKey(.unknown):
                method = "publickey (unknown key type)"
            case .keyboardInteractive(let submethods):
                method = "keyboard-interactive" + (submethods.isEmpty ? "" : " submethods \(quoted(submethods))")
            }
            return ["SSH_MSG_USERAUTH_REQUEST user \(quoted(message.username)) service \(message.service) method \(method)"]
        case .userAuthFailure(let message):
            return ["SSH_MSG_USERAUTH_FAILURE can continue: \(list(message.authentications))"
                + (message.partialSuccess ? " (partial success)" : "")]
        case .userAuthSuccess:
            return ["SSH_MSG_USERAUTH_SUCCESS"]
        case .userAuthBanner(let message):
            return ["SSH_MSG_USERAUTH_BANNER \(quoted(message.message))"]
        case .userAuthPKOK(let message):
            return ["SSH_MSG_USERAUTH_PK_OK \(String(message.key.keyPrefix)) (server will accept this key)"]
        case .userAuthInfoRequest(let message):
            var lines = ["SSH_MSG_USERAUTH_INFO_REQUEST name \(quoted(message.name)) instruction \(quoted(message.instruction)), "
                + "\(message.prompts.count) prompt(s)"]
            for (index, prompt) in message.prompts.enumerated() {
                lines.append("  prompt \(index + 1): \(quoted(prompt.prompt)) \(prompt.echo ? "echo" : "no echo")")
            }
            return lines
        case .userAuthInfoResponse(let message):
            return ["SSH_MSG_USERAUTH_INFO_RESPONSE \(message.responses.count) answer(s) (not logged)"]
        case .globalRequest(let message):
            let type: String
            switch message.type {
            case .tcpipForward(let host, let port): type = "tcpip-forward \(host):\(port)"
            case .cancelTcpipForward(let host, let port): type = "cancel-tcpip-forward \(host):\(port)"
            case .unknown(let name, _): type = name
            }
            return ["SSH_MSG_GLOBAL_REQUEST \(type)\(message.wantReply ? " (want reply)" : "")"]
        case .requestSuccess:
            return ["SSH_MSG_REQUEST_SUCCESS"]
        case .requestFailure:
            return ["SSH_MSG_REQUEST_FAILURE"]
        case .channelOpen(let message):
            let type: String
            switch message.type {
            case .session: type = "session"
            case .forwardedTCPIP(let forwarded): type = "forwarded-tcpip \(forwarded)"
            case .directTCPIP(let direct): type = "direct-tcpip \(direct)"
            }
            return ["SSH_MSG_CHANNEL_OPEN \(type) channel \(message.senderChannel), "
                + "window \(message.initialWindowSize), max packet \(message.maximumPacketSize)"]
        case .channelOpenConfirmation(let message):
            return ["SSH_MSG_CHANNEL_OPEN_CONFIRMATION channel \(message.recipientChannel) ↔ \(message.senderChannel), "
                + "window \(message.initialWindowSize), max packet \(message.maximumPacketSize)"]
        case .channelOpenFailure(let message):
            return ["SSH_MSG_CHANNEL_OPEN_FAILURE channel \(message.recipientChannel) reason \(message.reasonCode) "
                + "\(quoted(message.description))"]
        case .channelWindowAdjust, .channelData, .channelExtendedData:
            return []
        case .channelEOF(let message):
            return ["SSH_MSG_CHANNEL_EOF channel \(message.recipientChannel)"]
        case .channelClose(let message):
            return ["SSH_MSG_CHANNEL_CLOSE channel \(message.recipientChannel)"]
        case .channelRequest(let message):
            let type: String
            switch message.type {
            case .env(let name, _): type = "env \(name) (value not logged)"
            case .exec(let command): type = "exec (\(command.count)-character command, not logged)"
            case .exitStatus(let status): type = "exit-status \(status)"
            case .exitSignal(let signal, let coreDumped, let errorMessage, _):
                type = "exit-signal \(signal)\(coreDumped ? " (core dumped)" : "") \(quoted(errorMessage))"
            case .ptyReq(let pty):
                type = "pty-req \(pty.termVariable) \(pty.characterWidth)x\(pty.rowHeight)"
            case .shell: type = "shell"
            case .subsystem(let name): type = "subsystem \(name)"
            case .windowChange: return []
            case .xonXoff(let allowed): type = "xon-xoff \(allowed)"
            case .signal(let signal): type = "signal \(signal)"
            case .unknown: type = "(unknown type)"
            }
            return ["SSH_MSG_CHANNEL_REQUEST channel \(message.recipientChannel) \(type)\(message.wantReply ? " (want reply)" : "")"]
        case .channelSuccess(let message):
            return ["SSH_MSG_CHANNEL_SUCCESS channel \(message.recipientChannel)"]
        case .channelFailure(let message):
            return ["SSH_MSG_CHANNEL_FAILURE channel \(message.recipientChannel)"]
        }
    }
}

private func list(_ names: [Substring]) -> String {
    names.isEmpty ? "(none)" : names.joined(separator: ",")
}

/// One line when both directions agree, which is the usual case; two when they don't.
private func pair(_ label: String, _ clientToServer: [Substring], _ serverToClient: [Substring]) -> [String] {
    clientToServer == serverToClient
        ? ["  \(label): \(list(clientToServer))"]
        : ["  \(label) client→server: \(list(clientToServer))", "  \(label) server→client: \(list(serverToClient))"]
}

/// `"text"` with control characters escaped, so server text can't break up the log.
private func quoted(_ text: String) -> String {
    var result = "\""
    for scalar in text.unicodeScalars {
        switch scalar {
        case "\n": result += "\\n"
        case "\r": result += "\\r"
        case "\t": result += "\\t"
        case "\"": result += "\\\""
        default:
            if scalar.value < 0x20 || scalar.value == 0x7F {
                result += "\\u{" + String(scalar.value, radix: 16) + "}"
            } else {
                result.unicodeScalars.append(scalar)
            }
        }
    }
    return result + "\""
}

/// RFC 4253 section 11.1 reason codes.
private func disconnectReason(_ code: UInt32) -> String {
    switch code {
    case 1: return "host not allowed to connect"
    case 2: return "protocol error"
    case 3: return "key exchange failed"
    case 4: return "reserved"
    case 5: return "MAC error"
    case 6: return "compression error"
    case 7: return "service not available"
    case 8: return "protocol version not supported"
    case 9: return "host key not verifiable"
    case 10: return "connection lost"
    case 11: return "by application"
    case 12: return "too many connections"
    case 13: return "auth cancelled by user"
    case 14: return "no more auth methods available"
    case 15: return "illegal user name"
    default: return "unknown"
    }
}
