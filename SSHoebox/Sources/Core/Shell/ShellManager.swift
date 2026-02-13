import Foundation
import Combine

public class ShellManager: ObservableObject {
    @Published public var output: String = ""
    private var process: Process?
    private var inputPipe: Pipe?
    private var outputPipe: Pipe?
    
    public init() {
        startShell()
    }
    
    func startShell() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-i"] // Interactive mode
        
        let inputPipe = Pipe()
        let outputPipe = Pipe()
        
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        
        self.inputPipe = inputPipe
        self.outputPipe = outputPipe
        self.process = process
        
        outputPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if let string = String(data: data, encoding: .utf8) {
                DispatchQueue.main.async {
                    self?.output.append(string)
                    // Auto-scroll logic handled in View by watching output
                }
            }
        }
        
        do {
            try process.run()
        } catch {
            output.append("Error starting shell: \(error.localizedDescription)\n")
        }
    }
    
    public func send(command: String) {
        guard let inputPipe = inputPipe else { return }
        // Ensure command ends with newline
        let cmd = command.hasSuffix("\n") ? command : command + "\n"
        if let data = cmd.data(using: .utf8) {
            inputPipe.fileHandleForWriting.write(data)
        }
    }
    
    public func terminate() {
        process?.terminate()
    }
}
