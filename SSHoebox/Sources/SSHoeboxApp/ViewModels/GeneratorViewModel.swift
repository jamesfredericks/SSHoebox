import Foundation
import Combine
import SSHoeboxCore

class GeneratorViewModel: ObservableObject {
    @Published var options = GeneratorOptions()
    @Published var generatedPassword = ""
    
    init() {
        generate()
    }
    
    func generate() {
        generatedPassword = PasswordGenerator.generate(options: options)
    }
    
    func copyToClipboard() {
        // Implementation handled in View or here via NSPasteboard
    }
}
