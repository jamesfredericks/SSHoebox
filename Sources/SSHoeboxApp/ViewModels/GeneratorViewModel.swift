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

    /// Copies the generated value via ClipboardManager so it is auto-cleared
    /// after the user's configured timeout, like every other copied secret.
    @MainActor
    func copyToClipboard() {
        ClipboardManager.shared.copy(generatedPassword)
    }
}
