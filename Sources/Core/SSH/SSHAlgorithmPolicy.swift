import Foundation
import Citadel
import NIOSSH
import Crypto

/// The SSH algorithms SSHoebox negotiates, shared by terminal and SFTP connections.
///
/// NIOSSH always offers its bundled algorithms first:
/// - key exchange: ecdh-sha2-nistp384/256/521 and curve25519-sha256
/// - ciphers: aes256-gcm@openssh.com and aes128-gcm@openssh.com
/// - host keys: ssh-ed25519 and ecdsa-sha2-nistp256/384/521
///
/// On top of those this adds:
/// - diffie-hellman-group14-sha256, for servers without elliptic-curve key exchange.
/// - aes128-ctr with hmac-sha2-256/512, for servers without AES-GCM. (Citadel's hmac-sha1
///   option is removed by an SSHoebox patch in AES.swift.)
/// - the ETM MAC names some servers require during negotiation; AES-GCM ignores the MAC.
/// - ssh-rsa host keys, offered last, so servers that only have an RSA host key still connect.
///   NIOSSH ties the host key algorithm name to the key's blob type, so an RSA host key can
///   only be verified with the "ssh-rsa" (SHA-1) signature algorithm, not rsa-sha2-256/512.
///   Servers with an Ed25519 or ECDSA host key always negotiate those instead.
///
/// Citadel's `SSHAlgorithms.all` also enables diffie-hellman-group14-sha1, which this drops.
public enum SSHAlgorithmPolicy {
    public static let algorithms: SSHAlgorithms = {
        var algorithms = SSHAlgorithms()
        algorithms.transportProtectionSchemes = .add([
            AES128CTR.self,
            ETMMACCompatScheme.self,
        ])
        algorithms.keyExchangeAlgorithms = .add([
            DiffieHellmanGroup14Sha256.self,
        ])
        algorithms.publicKeyAlgorihtms = .add([
            (Insecure.RSA.PublicKey.self, Insecure.RSA.Signature.self),
        ])
        return algorithms
    }()
}
