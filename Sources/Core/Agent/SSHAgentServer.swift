import Foundation
import NIO


public class SSHAgentServer {
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private var channel: Channel?
    private let socketPath: String
    private weak var delegate: SSHAgentDelegate?
    
    public init(socketPath: String, delegate: SSHAgentDelegate) {
        self.socketPath = socketPath
        self.delegate = delegate
    }
    
    public func start() async throws {
        // Remove existing socket file if it exists
        if FileManager.default.fileExists(atPath: socketPath) {
            try FileManager.default.removeItem(atPath: socketPath)
        }
        
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [weak delegate = self.delegate] channel in
                channel.pipeline.addHandler(ByteToMessageHandler(SSHAgentFrameDecoder()))
                    .flatMap {
                        if let delegate = delegate {
                            return channel.pipeline.addHandler(SSHAgentHandler(delegate: delegate))
                        } else {
                            return channel.close()
                        }
                    }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_keepalive), value: 1)
            
        self.channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
        print("SSH Agent listening on \(socketPath)")
    }
    
    public func stop() async throws {
        try await channel?.close()
        try await group.shutdownGracefully()
        
        // Clean up socket file
        if FileManager.default.fileExists(atPath: socketPath) {
            try? FileManager.default.removeItem(atPath: socketPath)
        }
    }
}
