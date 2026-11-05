import Foundation
import Citadel
import NIOCore
import NIOPosix
import NIOSSH

/// A local port forward (`ssh -L`) running over an SSH connection: listens on this Mac and
/// carries each accepted connection through a `direct-tcpip` channel to the destination.
public final class LocalPortForwarder: @unchecked Sendable {
    public let forward: PortForward
    private let listener: Channel
    private let lock = NSLock()
    private var _connections = 0

    /// Connections currently open through the tunnel.
    public var openConnections: Int { lock.withLock { _connections } }

    private init(forward: PortForward, listener: Channel) {
        self.forward = forward
        self.listener = listener
    }

    /// Starts listening on `forward.bindAddress:localPort`. Throws if the port can't be bound
    /// (already in use, or below 1024 without privileges). `onEvent` reports problems with
    /// individual connections, such as the server refusing to open the channel.
    public static func start(_ forward: PortForward, over client: SSHClient,
                             onEvent: @escaping @Sendable (String) -> Void = { _ in }) async throws -> LocalPortForwarder {
        let box = ForwarderBox()
        // Same event loop as the SSH connection: the glue handlers call each other directly.
        let bootstrap = ServerBootstrap(group: client.eventLoop)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .childChannelOption(ChannelOptions.autoRead, value: false)
            .childChannelInitializer { local in
                let (localGlue, remoteGlue) = ForwardingGlueHandler.matchedPair()
                let origin = local.remoteAddress ?? (try? SocketAddress(ipAddress: "127.0.0.1", port: 0))
                let opened = local.eventLoop.makePromise(of: Void.self)
                opened.completeWithTask {
                    try await local.pipeline.addHandler(localGlue).get()
                    _ = try await client.createDirectTCPIPChannel(
                        using: SSHChannelType.DirectTCPIP(targetHost: forward.remoteHost, targetPort: forward.remotePort,
                                                          originatorAddress: origin!)
                    ) { channel in
                        channel.pipeline.addHandler(remoteGlue)
                    }
                    box.value?.changeConnections(by: 1)
                    local.closeFuture.whenComplete { _ in box.value?.changeConnections(by: -1) }
                    local.read()
                }
                return opened.futureResult.flatMapError { error in
                    onEvent("tunnel \(forward.summary): couldn't open a connection to \(forward.remoteHost):"
                            + "\(forward.remotePort) through the server (\(LoginTrace.describe(error)))")
                    return local.close()
                }
            }
        let listener = try await bootstrap.bind(host: forward.bindAddress, port: forward.localPort).get()
        let forwarder = LocalPortForwarder(forward: forward, listener: listener)
        box.value = forwarder
        return forwarder
    }

    private func changeConnections(by delta: Int) {
        lock.withLock { _connections += delta }
    }

    /// Stops listening. Connections already open are left to finish.
    public func stop() {
        listener.close(promise: nil)
    }
}

private final class ForwarderBox: @unchecked Sendable {
    weak var value: LocalPortForwarder?
}

/// Joins two channels on the same event loop, passing everything read on one to the other,
/// with back-pressure and half-closure. Adapted from SwiftNIO's `GlueHandler` example.
final class ForwardingGlueHandler: ChannelDuplexHandler {
    typealias InboundIn = NIOAny
    typealias OutboundIn = NIOAny
    typealias OutboundOut = NIOAny

    private var partner: ForwardingGlueHandler?
    private var context: ChannelHandlerContext?
    private var pendingRead = false

    private init() {}

    static func matchedPair() -> (ForwardingGlueHandler, ForwardingGlueHandler) {
        let first = ForwardingGlueHandler()
        let second = ForwardingGlueHandler()
        first.partner = second
        second.partner = first
        return (first, second)
    }

    private func partnerWrite(_ data: NIOAny) { context?.write(data, promise: nil) }
    private func partnerFlush() { context?.flush() }
    private func partnerWriteEOF() { context?.close(mode: .output, promise: nil) }
    private func partnerCloseFull() { context?.close(promise: nil) }
    private func partnerBecameWritable() {
        if pendingRead {
            pendingRead = false
            context?.read()
        }
    }
    private var partnerWritable: Bool { context?.channel.isWritable ?? false }

    func handlerAdded(context: ChannelHandlerContext) { self.context = context }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        partner = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) { partner?.partnerWrite(data) }

    func channelReadComplete(context: ChannelHandlerContext) { partner?.partnerFlush() }

    func channelInactive(context: ChannelHandlerContext) { partner?.partnerCloseFull() }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? ChannelEvent, case .inputClosed = event {
            partner?.partnerWriteEOF()
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        partner?.partnerCloseFull()
        context.close(promise: nil)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable { partner?.partnerBecameWritable() }
    }

    func read(context: ChannelHandlerContext) {
        if let partner, partner.partnerWritable {
            context.read()
        } else {
            pendingRead = true
        }
    }
}
