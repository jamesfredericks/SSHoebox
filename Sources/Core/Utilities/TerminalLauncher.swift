import Foundation
import AppKit

public struct TerminalLauncher {
    public static func openInTerminal(command: String, password: String? = nil, isInteractive: Bool = false) async {
        // Simple input sanitization to prevent command injection
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-@:/")
        guard command.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            print("Error: Command contains invalid characters. Aborting.")
            return
        }
        
        // Run file operations on a background thread to avoid blocking the UI
        Task.detached(priority: .userInitiated) {
            var scriptContent = ""
            
            // If interactive mode OR no password, use plain shell script
            if isInteractive || password == nil {
                scriptContent = """
                #!/bin/sh
                echo "Starting session..."
                \(command)
                echo "\\n[Session finished. Close this window to exit.]"
                # read
                """
            } else {
                // Use expect script for password automation
                // Escape special characters in password for Tcl/Expect
                let escapedPassword = password!
                    .replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"")
                    .replacingOccurrences(of: "[", with: "\\[")
                    .replacingOccurrences(of: "]", with: "\\]")
                    .replacingOccurrences(of: "{", with: "\\{")
                    .replacingOccurrences(of: "}", with: "\\}")
                    .replacingOccurrences(of: "$", with: "\\$")
                    .replacingOccurrences(of: ";", with: "\\;")
                
                scriptContent = """
                #!/usr/bin/expect -f
                
                # Don't show the password in the output
                log_user 1
                
                set timeout -1
                spawn \(command)
                
                expect {
                    "yes/no" { 
                        send "yes\\r"
                        exp_continue 
                    }
                    "assword:" { 
                        log_user 0
                        send "\(escapedPassword)\\r" 
                        log_user 1
                    }
                }
                
                # Hand over control to the user
                interact
                """
            }
            
            let tempDir = FileManager.default.temporaryDirectory
            let fileName = "ssh_session_\(UUID().uuidString).command"
            let fileURL = tempDir.appendingPathComponent(fileName)
            
            do {
                try scriptContent.write(to: fileURL, atomically: true, encoding: .utf8)
                
                // Set executable permissions (rwxr-xr-x) for shell, strict for expect (rwx------)
                let perms = password != nil ? 0o700 : 0o755
                let attributes: [FileAttributeKey: Any] = [.posixPermissions: perms]
                try FileManager.default.setAttributes(attributes, ofItemAtPath: fileURL.path)
                
                // FIX: NSWorkspace.shared.open MUST be on MainActor
                await MainActor.run {
                    _ = NSWorkspace.shared.open(fileURL)
                }

                // Delete the script file after a delay so Terminal has time to read it.
                // This is especially important for Expect scripts that contain plaintext passwords.
                try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
                try? FileManager.default.removeItem(at: fileURL)

            } catch {
                print("Failed to launch terminal: \(error)")
            }
        }
    }
}
