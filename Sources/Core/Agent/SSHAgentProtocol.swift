import Foundation
import NIO
import NIOSSH
import CryptoKit

enum SSHAgentMessage {
    case requestIdentities
    case signRequest(key: Data, data: Data, flags: UInt32)
    case failure
    case success
    case identitiesAnswer([(key: Data, comment: String)])
    case signResponse(signature: Data)
    
    // Protocol constants from RFC 4253 / OpenSSH agent protocol
    static let SSH2_AGENTC_REQUEST_IDENTITIES: UInt8 = 11
    static let SSH2_AGENTC_SIGN_REQUEST: UInt8 = 13
    static let SSH2_AGENT_IDENTITIES_ANSWER: UInt8 = 12
    static let SSH2_AGENT_SIGN_RESPONSE: UInt8 = 14
    static let SSH_AGENT_FAILURE: UInt8 = 5
    static let SSH_AGENT_SUCCESS: UInt8 = 6
}

struct SSHAgentProtocol {
    
    /// Largest message body the agent accepts, matching OpenSSH's `AGENT_MAX_LEN`.
    /// Anything bigger is treated as hostile and the connection is dropped, so a local
    /// process can't make the app buffer up to 4 GiB by sending a huge length prefix.
    static let maxMessageLength = 256 * 1024
    
    static func parse(buffer: inout ByteBuffer) throws -> SSHAgentMessage {
        guard let messageType = buffer.readInteger(as: UInt8.self) else {
            throw SSHAgentError.invalidMessage
        }
        
        switch messageType {
        case SSHAgentMessage.SSH2_AGENTC_REQUEST_IDENTITIES:
            return .requestIdentities
            
        case SSHAgentMessage.SSH2_AGENTC_SIGN_REQUEST:
            guard let keyBlob = readBlob(from: &buffer),
                  let data = readBlob(from: &buffer),
                  let flags = buffer.readInteger(as: UInt32.self) else {
                throw SSHAgentError.invalidMessage
            }
            return .signRequest(key: keyBlob, data: data, flags: flags)
            
        default:
            throw SSHAgentError.unknownMessageType(messageType)
        }
    }
    
    static func serialize(message: SSHAgentMessage, into buffer: inout ByteBuffer) {
        switch message {
        case .failure:
            buffer.writeInteger(SSHAgentMessage.SSH_AGENT_FAILURE)
            
        case .success:
            buffer.writeInteger(SSHAgentMessage.SSH_AGENT_SUCCESS)
            
        case .identitiesAnswer(let identities):
            buffer.writeInteger(SSHAgentMessage.SSH2_AGENT_IDENTITIES_ANSWER)
            buffer.writeInteger(UInt32(identities.count))
            for (key, comment) in identities {
                writeBlob(key, to: &buffer)
                writeString(comment, to: &buffer)
            }
            
        case .signResponse(let signature):
            buffer.writeInteger(SSHAgentMessage.SSH2_AGENT_SIGN_RESPONSE)
            writeBlob(signature, to: &buffer)
            
        default:
            break // Clients send requests, server sends responses
        }
    }

    // MARK: - Client side

    /// Writes a request as an agent client sends it (no length prefix).
    static func serialize(request: SSHAgentMessage, into buffer: inout ByteBuffer) {
        switch request {
        case .requestIdentities:
            buffer.writeInteger(SSHAgentMessage.SSH2_AGENTC_REQUEST_IDENTITIES)

        case .signRequest(let key, let data, let flags):
            buffer.writeInteger(SSHAgentMessage.SSH2_AGENTC_SIGN_REQUEST)
            writeBlob(key, to: &buffer)
            writeBlob(data, to: &buffer)
            buffer.writeInteger(flags)

        default:
            break // Responses are only written by the server side
        }
    }

    /// Reads a reply from an agent (one frame, length prefix already removed).
    static func parseResponse(buffer: inout ByteBuffer) throws -> SSHAgentMessage {
        guard let messageType = buffer.readInteger(as: UInt8.self) else {
            throw SSHAgentError.invalidMessage
        }

        switch messageType {
        case SSHAgentMessage.SSH_AGENT_FAILURE:
            return .failure

        case SSHAgentMessage.SSH_AGENT_SUCCESS:
            return .success

        case SSHAgentMessage.SSH2_AGENT_IDENTITIES_ANSWER:
            guard let count = buffer.readInteger(as: UInt32.self) else {
                throw SSHAgentError.invalidMessage
            }
            var identities: [(key: Data, comment: String)] = []
            for _ in 0..<count {
                guard let key = readBlob(from: &buffer), let comment = readBlob(from: &buffer) else {
                    throw SSHAgentError.invalidMessage
                }
                identities.append((key, String(decoding: comment, as: UTF8.self)))
            }
            return .identitiesAnswer(identities)

        case SSHAgentMessage.SSH2_AGENT_SIGN_RESPONSE:
            guard let signature = readBlob(from: &buffer) else {
                throw SSHAgentError.invalidMessage
            }
            return .signResponse(signature: signature)

        default:
            throw SSHAgentError.unknownMessageType(messageType)
        }
    }

    // MARK: - Helpers
    
    private static func readBlob(from buffer: inout ByteBuffer) -> Data? {
        guard let length = buffer.readInteger(as: UInt32.self),
              let bytes = buffer.readBytes(length: Int(length)) else {
            return nil
        }
        return Data(bytes)
    }
    
    private static func writeBlob(_ data: Data, to buffer: inout ByteBuffer) {
        buffer.writeInteger(UInt32(data.count))
        buffer.writeBytes(data)
    }
    
    private static func writeString(_ string: String, to buffer: inout ByteBuffer) {
        let data = string.data(using: .utf8) ?? Data()
        writeBlob(data, to: &buffer)
    }
}

public enum SSHAgentError: Error {
    case invalidMessage
    case unknownMessageType(UInt8)
    case messageTooLarge(UInt32)
    /// A connection from another user (or whose credentials couldn't be read).
    case unauthorizedPeer(uid: uid_t?)
    /// The socket's directory isn't a directory owned by the current user.
    case insecureSocketDirectory(String)
    /// Something other than a socket already exists at the socket path.
    case socketPathInUse(String)
    /// The socket path doesn't fit in `sockaddr_un.sun_path` (104 bytes on macOS).
    case socketPathTooLong(String)
    /// `start()` was called on a server that has been stopped.
    case serverStopped
    /// `start()` was called twice on the same server.
    case serverAlreadyStarted
}

/// Errors from talking to an external agent (Bitwarden, 1Password, `ssh-agent`) as a client.
public enum SSHAgentClientError: LocalizedError, Equatable {
    /// Nothing is listening at the socket path.
    case agentNotRunning(String)
    /// The socket belongs to another user, or its owner couldn't be checked.
    case untrustedAgent(String)
    /// The socket is SSHoebox's own agent, which only serves keys already in this vault.
    case ownAgent
    /// The agent no longer offers the key this credential refers to.
    case keyNotFound(String)
    /// The agent refused to sign: the user declined the prompt, or the agent is locked.
    case signingRefused
    /// No reply within the time allowed (an approval prompt left unanswered).
    case timedOut
    /// The agent closed the connection or sent something that isn't a valid reply.
    case protocolError
    /// A key type SSHoebox can't log in with through an agent (e.g. RSA).
    case unsupportedKeyType(String)

    public var errorDescription: String? {
        switch self {
        case .agentNotRunning(let path):
            return "No SSH agent is running at \(path). In Bitwarden, turn on Settings → SSH agent."
        case .untrustedAgent(let path):
            return "The SSH agent socket at \(path) isn't owned by you, so it wasn't used."
        case .ownAgent:
            return "That socket is SSHoebox's own agent. Use the key credential directly instead."
        case .keyNotFound(let fingerprint):
            return "The SSH agent doesn't offer the key \(fingerprint). Unlock your password manager, or pick the key again."
        case .signingRefused:
            return "The SSH agent declined to sign (request denied, or the vault is locked)."
        case .timedOut:
            return "The SSH agent didn't answer in time. Approve the request in your password manager and try again."
        case .protocolError:
            return "The SSH agent sent an invalid reply."
        case .unsupportedKeyType(let type):
            return "\(type) keys can't be used through an SSH agent yet. Use an Ed25519 or ECDSA key."
        }
    }
}
