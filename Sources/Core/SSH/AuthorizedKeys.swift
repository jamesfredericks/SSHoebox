import Foundation
import Citadel
import Crypto
import NIOSSH

/// Putting a key's public half in a server's `~/.ssh/authorized_keys`, like `ssh-copy-id`.
public enum AuthorizedKeys {
    public enum InstallResult: Equatable {
        case added
        case alreadyPresent
    }

    public enum KeyError: LocalizedError {
        case passphraseRequired
        case unreadable(String)

        public var errorDescription: String? {
            switch self {
            case .passphraseRequired:
                return "This key is encrypted and its public half can't be read without the passphrase."
            case .unreadable(let detail):
                return "The public key can't be read from this key (\(detail))."
            }
        }
    }

    /// The OpenSSH public key line (`type base64 comment`) of a stored private key. For keys
    /// in OpenSSH format it's read from the key's unencrypted public section, so an encrypted
    /// key needs no passphrase; other formats need one if they're encrypted.
    public static func publicKeyLine(fromPEM pem: String, passphrase: String? = nil, comment: String = "") throws -> String {
        let blob: Data
        if let section = openSSHPublicSection(pem) {
            blob = section
        } else {
            switch StoredLoginKey.read(pem: pem, passphrase: passphrase) {
            case .key(.ed25519(let key)):
                blob = wireBlob(of: NIOSSHPrivateKey(ed25519Key: key).publicKey)
            case .key(.rsa(let key)):
                blob = key.publicKeyBlob
            case .key(.ecdsa(let key)):
                blob = wireBlob(of: key.privateKey.publicKey)
            case .needsPassphrase:
                throw KeyError.passphraseRequired
            case .wrongPassphrase:
                throw KeyError.unreadable("wrong passphrase")
            case .unsupported(let detail):
                throw KeyError.unreadable(detail)
            case .invalid(let error):
                throw KeyError.unreadable(error.localizedDescription)
            }
        }
        guard let type = keyType(ofBlob: blob) else { throw KeyError.unreadable("malformed public key") }
        let cleanComment = sanitizedComment(comment)
        return "\(type) \(blob.base64EncodedString())" + (cleanComment.isEmpty ? "" : " \(cleanComment)")
    }

    /// A command that appends `publicKeyLine` to `~/.ssh/authorized_keys` unless the same key
    /// (type and blob, whatever the comment) is already there, creating the folder and file
    /// with private permissions if needed. Prints a marker `parse(output:)` reads. Runs under
    /// `sh`, so it works whatever the user's login shell is.
    public static func installCommand(for publicKeyLine: String) throws -> String {
        let fields = publicKeyLine.split(separator: " ", omittingEmptySubsequences: true)
        guard fields.count >= 2,
              fields[0].allSatisfy({ $0.isLetter || $0.isNumber || "-@.".contains($0) }),
              fields[1].allSatisfy({ $0.isLetter || $0.isNumber || "+/=".contains($0) }) else {
            throw KeyError.unreadable("not an OpenSSH public key line")
        }
        let key = "\(fields[0]) \(fields[1])"
        let comment = sanitizedComment(fields.dropFirst(2).joined(separator: " "))
        let line = comment.isEmpty ? key : "\(key) \(comment)"
        // Nothing interpolated below can contain a quote, '$', '`' or '\': the key fields and
        // comment were checked or filtered above.
        let script = [
            "umask 077",
            "mkdir -p \"$HOME/.ssh\" && touch \"$HOME/.ssh/authorized_keys\" || exit 1",
            "f=\"$HOME/.ssh/authorized_keys\"",
            "if grep -qF \"\(key)\" \"$f\"; then echo \(presentMarker); exit 0; fi",
            // Don't join the new key onto a last line that has no newline.
            "if [ -s \"$f\" ] && [ -n \"$(tail -c 1 \"$f\")\" ]; then echo >> \"$f\"; fi",
            "printf \"%s\\n\" \"\(line)\" >> \"$f\" && echo \(addedMarker)",
        ].joined(separator: "; ")
        return "sh -c '\(script)'"
    }

    /// Reads the result of `installCommand`'s output, or nil if neither marker is there.
    public static func parse(output: String) -> InstallResult? {
        if output.contains(addedMarker) { return .added }
        if output.contains(presentMarker) { return .alreadyPresent }
        return nil
    }

    static let addedMarker = "SSHOEBOX_KEY_ADDED"
    static let presentMarker = "SSHOEBOX_KEY_PRESENT"

    // MARK: - Helpers

    /// Comments are free text in authorized_keys; keep a safe subset.
    static func sanitizedComment(_ comment: String) -> String {
        String(comment.filter { $0.isLetter || $0.isNumber || " @._-:+".contains($0) }.prefix(120))
            .trimmingCharacters(in: .whitespaces)
    }

    private static func wireBlob(of key: NIOSSHPublicKey) -> Data {
        let line = String(openSSHPublicKey: key)
        return line.split(separator: " ").dropFirst().first.flatMap { Data(base64Encoded: String($0)) } ?? Data()
    }

    private static func keyType(ofBlob blob: Data) -> String? {
        guard blob.count > 4 else { return nil }
        let length = blob.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        guard length > 0, blob.count >= 4 + length else { return nil }
        return String(data: blob.dropFirst(4).prefix(length), encoding: .utf8)
    }

    /// The public key blob from an `openssh-key-v1` key's header, which is never encrypted.
    private static func openSSHPublicSection(_ pem: String) -> Data? {
        let lines = SSHKeyParser.normalizedPEM(pem).split(whereSeparator: \.isNewline)
        guard lines.first?.contains("BEGIN OPENSSH PRIVATE KEY") == true,
              let data = Data(base64Encoded: lines.filter { !$0.hasPrefix("-----") }.joined()) else { return nil }
        var bytes = Array(data)[...]
        let magic = Array("openssh-key-v1".utf8) + [0]
        guard bytes.starts(with: magic) else { return nil }
        bytes = bytes.dropFirst(magic.count)
        func readString() -> ArraySlice<UInt8>? {
            guard bytes.count >= 4 else { return nil }
            let length = bytes.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            bytes = bytes.dropFirst(4)
            guard bytes.count >= length else { return nil }
            defer { bytes = bytes.dropFirst(length) }
            return bytes.prefix(length)
        }
        guard readString() != nil, readString() != nil, readString() != nil, // cipher, kdf, kdf options
              bytes.count >= 4, bytes.prefix(4).reduce(0, { $0 << 8 | Int($1) }) == 1 else { return nil }
        bytes = bytes.dropFirst(4)
        return readString().map { Data($0) }
    }
}

/// Runs one command on a host over a connection of its own, then disconnects. Nothing can
/// answer login prompts here (like SFTP), so the host must log in with a stored password or key.
public enum SSHCommandRunner {
    public enum RunError: LocalizedError {
        case needsPassphrase
        case cannotLogIn(String)

        public var errorDescription: String? {
            switch self {
            case .needsPassphrase:
                return "The login key is encrypted. Open a terminal session to the host first, then try again."
            case .cannotLogIn(let reason):
                return reason
            }
        }
    }

    public static func run(_ command: String, target: SSHLogin, via jumps: [SSHLogin] = [],
                           repository: KnownHostRepository?, purpose: String) async throws -> String {
        let trace = LoginTrace()
        trace.begin("SSH (\(purpose))", host: target.host, port: target.port, username: target.username,
                    method: target.auth.methodDescriptionForTrace)
        let preparer = SSHLoginPreparer(repository: repository, trace: trace, prompter: nil)
        var prepared: [PreparedLogin] = []
        for login in jumps + [target] {
            switch await preparer.prepare(login) {
            case .ready(let step): prepared.append(step)
            case .needsPassphrase: throw RunError.needsPassphrase
            case .failed(let message): throw RunError.cannotLogIn(message)
            }
        }
        let route: SSHRoute
        do {
            route = try await SSHRoute.connect(prepared, repository: repository, trace: trace)
        } catch {
            trace.error("failed: \(LoginTrace.describe(error))")
            throw error
        }
        trace.info("auth: SUCCESS, logged in; running the command (\(purpose))")
        defer { Task { await route.close() } }
        do {
            let output = String(buffer: try await route.client.executeCommand(command))
            trace.info("exec: command finished")
            return output
        } catch {
            trace.error("exec: \(LoginTrace.describe(error))")
            throw error
        }
    }
}
