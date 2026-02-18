import Foundation
import NIO
import NIOSSH
import CryptoKit

public protocol SSHAgentDelegate: AnyObject {
    func getIdentities() async -> [(key: Data, comment: String)]
    func sign(key: Data, data: Data, flags: UInt32) async throws -> Data
}

final class SSHAgentHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    
    private weak var delegate: SSHAgentDelegate?
    
    init(delegate: SSHAgentDelegate) {
        self.delegate = delegate
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = self.unwrapInboundIn(data)
        
        // Handle framing: 4-byte length prefix
        // For simplicity in this initial version, we assume complete messages or use a ByteToMessageDecoder in the pipeline.
        // We'll implemented the framing logic here for now to keep it simple, or better, add a LengthFieldBasedFrameDecoder to the pipeline.
        
        // Assuming the pipeline has `LengthFieldBasedFrameDecoder`
        
        do {
            let message = try SSHAgentProtocol.parse(buffer: &buffer)
            handleMessage(context: context, message: message)
        } catch {
            print("Agent protocol error: \(error)")
            sendFailure(context: context)
        }
    }
    
    private func handleMessage(context: ChannelHandlerContext, message: SSHAgentMessage) {
        Task {
            do {
                switch message {
                case .requestIdentities:
                    let identities = await delegate?.getIdentities() ?? []
                    let response = SSHAgentMessage.identitiesAnswer(identities)
                    sendResponse(context: context, message: response)
                    
                case .signRequest(let key, let data, let flags):
                    do {
                        if let signature = try await delegate?.sign(key: key, data: data, flags: flags) {
                            let response = SSHAgentMessage.signResponse(signature: signature)
                            sendResponse(context: context, message: response)
                        } else {
                            sendFailure(context: context)
                        }
                    } catch {
                        sendFailure(context: context)
                    }
                    
                default:
                    // Unsupported message
                    sendFailure(context: context)
                }
        }
    }
}
    
    private func sendResponse(context: ChannelHandlerContext, message: SSHAgentMessage) {
        // Run on EventLoop to safely write to channel
        context.eventLoop.execute {
            var contentBuffer = context.channel.allocator.buffer(capacity: 1024)
            SSHAgentProtocol.serialize(message: message, into: &contentBuffer)
            
            // Add length prefix
            var frameBuffer = context.channel.allocator.buffer(capacity: 4 + contentBuffer.readableBytes)
            frameBuffer.writeInteger(UInt32(contentBuffer.readableBytes))
            frameBuffer.writeBuffer(&contentBuffer)
            
            context.writeAndFlush(self.wrapOutboundOut(frameBuffer), promise: nil)
        }
    }
    
    private func sendFailure(context: ChannelHandlerContext) {
        sendResponse(context: context, message: .failure)
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Agent handler error: \(error)")
        context.close(promise: nil)
    }
}

final class SSHAgentFrameDecoder: ByteToMessageDecoder {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    
    var length: UInt32?
    
    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        if self.length == nil {
            guard buffer.readableBytes >= 4 else { return .needMoreData }
            self.length = buffer.readInteger(as: UInt32.self)
        }
        
        guard let length = self.length else { return .needMoreData }
        
        guard buffer.readableBytes >= length else { return .needMoreData }
        
        // We have the full frame
        let frame = buffer.readSlice(length: Int(length))!
        self.length = nil
        context.fireChannelRead(self.wrapInboundOut(frame))
        return .continue
    }
    
    func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        return try decode(context: context, buffer: &buffer)
    }
}
