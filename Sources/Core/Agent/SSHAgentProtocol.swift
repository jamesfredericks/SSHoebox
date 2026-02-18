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
}
