import Foundation
import NIO
import NIOSSH
import CryptoKit

public protocol SSHAgentDelegate: AnyObject {
    func getIdentities() async -> [(key: Data, comment: String)]
    func sign(key: Data, data: Data, flags: UInt32) async throws -> Data
}

/// Handles one agent connection.
///
/// Requests are answered strictly in the order they arrive: `channelRead` only queues
/// them, and a single worker task per connection processes the queue one request at a
/// time. A slow sign request therefore can't be overtaken by a later, faster reply,
/// which clients (which match replies to requests purely by order) would misread.
final class SSHAgentHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    /// Most requests a connection may have waiting behind the one in progress. A client
    /// that pipelines more than this isn't waiting for replies, so it is disconnected.
    static let maxQueuedRequests = 64

    private enum Request {
        case message(SSHAgentMessage)
        case invalid
    }

    private weak var delegate: SSHAgentDelegate?
    private var requests: AsyncStream<Request>.Continuation?
    private var worker: Task<Void, Never>?

    init(delegate: SSHAgentDelegate) {
        self.delegate = delegate
    }

    func handlerAdded(context: ChannelHandlerContext) {
        var continuation: AsyncStream<Request>.Continuation!
        let stream = AsyncStream<Request>(bufferingPolicy: .bufferingOldest(Self.maxQueuedRequests)) {
            continuation = $0
        }
        requests = continuation

        let channel = context.channel
        worker = Task { [weak self] in
            for await request in stream {
                guard let self = self else { return }
                let reply = await self.process(request)
                Self.send(reply, on: channel)
            }
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        finish()
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish()
        context.fireChannelInactive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = self.unwrapInboundIn(data)

        let request: Request
        do {
            request = .message(try SSHAgentProtocol.parse(buffer: &buffer))
        } catch {
            // Unknown or malformed requests still get a reply, queued behind earlier ones.
            print("Agent protocol error: \(error)")
            request = .invalid
        }

        if case .dropped = requests?.yield(request) {
            print("SSH Agent: too many queued requests, closing connection")
            context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Agent handler error: \(error)")
        context.close(promise: nil)
    }

    private func finish() {
        requests?.finish()
        requests = nil
        worker?.cancel()
        worker = nil
    }

    // MARK: - Request processing

    private func process(_ request: Request) async -> SSHAgentMessage {
        guard case .message(let message) = request, let delegate = delegate else {
            return .failure
        }

        switch message {
        case .requestIdentities:
            return .identitiesAnswer(await delegate.getIdentities())

        case .signRequest(let key, let data, let flags):
            do {
                return .signResponse(signature: try await delegate.sign(key: key, data: data, flags: flags))
            } catch {
                return .failure
            }

        default:
            // Unsupported message
            return .failure
        }
    }

    /// Frames and writes a reply. `Channel` writes are thread-safe and keep their order.
    private static func send(_ message: SSHAgentMessage, on channel: Channel) {
        var contentBuffer = channel.allocator.buffer(capacity: 1024)
        SSHAgentProtocol.serialize(message: message, into: &contentBuffer)

        // Add length prefix
        var frameBuffer = channel.allocator.buffer(capacity: 4 + contentBuffer.readableBytes)
        frameBuffer.writeInteger(UInt32(contentBuffer.readableBytes))
        frameBuffer.writeBuffer(&contentBuffer)

        channel.writeAndFlush(frameBuffer, promise: nil)
    }
}

final class SSHAgentFrameDecoder: ByteToMessageDecoder {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    
    var length: UInt32?
    
    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        if self.length == nil {
            guard buffer.readableBytes >= 4 else { return .needMoreData }
            let length = buffer.readInteger(as: UInt32.self)!
            // Reject oversized frames before buffering them; throwing closes the connection.
            guard length <= SSHAgentProtocol.maxMessageLength else {
                throw SSHAgentError.messageTooLarge(length)
            }
            self.length = length
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
