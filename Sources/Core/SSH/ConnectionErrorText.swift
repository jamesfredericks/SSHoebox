import Foundation
import NIOCore
import NIOPosix

/// Plain-language text for the network errors a connection can fail with, in place of
/// SwiftNIO's internal descriptions. The login log keeps the full detail.
public enum ConnectionErrorText {
    public static func describe(_ error: Error) -> String? {
        if let error = error as? NIOConnectionError {
            if error.dnsAError != nil || error.dnsAAAAError != nil,
               error.connectionErrors.isEmpty {
                return "Couldn't find \(error.host): the name doesn't resolve (check the hostname or DNS)."
            }
            if let errno = error.connectionErrors.lazy.compactMap({ ($0.error as? IOError)?.errnoCode }).first {
                return describe(errno: errno, host: error.host, port: error.port)
            }
            if error.connectionErrors.contains(where: {
                if case .connectTimeout? = $0.error as? ChannelError { return true }
                return false
            }) {
                return "Timed out connecting to \(error.host):\(error.port)."
            }
            return "Couldn't connect to \(error.host):\(error.port)."
        }
        if let error = error as? ChannelError, case .connectTimeout = error {
            return "Timed out connecting (no answer from the server; a firewall may be dropping the connection)."
        }
        if let error = error as? IOError {
            return describe(errno: error.errnoCode, host: nil, port: nil)
        }
        return nil
    }

    private static func describe(errno: Int32, host: String?, port: Int?) -> String {
        let target = host.map { "\($0)" + (port.map { ":\($0)" } ?? "") } ?? "the server"
        switch errno {
        case ECONNREFUSED: return "Connection refused by \(target): nothing is listening on that port, or a firewall rejects it."
        case ETIMEDOUT: return "Timed out connecting to \(target)."
        case EHOSTUNREACH, ENETUNREACH: return "\(target) is unreachable from this network (VPN off?)."
        case ECONNRESET: return "\(target) closed the connection."
        default: return "Couldn't connect to \(target): \(String(cString: strerror(errno)))."
        }
    }
}
