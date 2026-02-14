import CryptoKit

public struct SSHConnection {
    public static func generateCommand(for host: SavedHost, user: String?, key: SymmetricKey) -> String {
        let hostUser = host.decryptedUser(using: key)
        let hostname = host.decryptedHostname(using: key)
        
        let username = user ?? hostUser
        let portFlag = host.port != 22 ? "-p \(host.port)" : ""
        
        // Basic SSH command: ssh -p 2222 user@hostname
        // Use -o StrictHostKeyChecking=accept-new for V1 friendliness if desired, 
        // but default is safer.
        
        let target = username.isEmpty ? hostname : "\(username)@\(hostname)"
        
        // Remove empty components
        let components = ["ssh", portFlag, target].filter { !$0.isEmpty }
        return components.joined(separator: " ")
    }
}
