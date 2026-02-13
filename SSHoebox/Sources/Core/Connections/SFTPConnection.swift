import CryptoKit

public struct SFTPConnection {
    public static func generateCommand(for host: SavedHost, user: String?, key: SymmetricKey) -> String {
        let hostUser = host.decryptedUser(using: key)
        let hostname = host.decryptedHostname(using: key)
        
        let username = user ?? hostUser
        let portFlag = host.port != 22 ? "-P \(host.port)" : ""
        
        let target = username.isEmpty ? hostname : "\(username)@\(hostname)"
        
        let components = ["sftp", portFlag, target].filter { !$0.isEmpty }
        return components.joined(separator: " ")
    }
}
