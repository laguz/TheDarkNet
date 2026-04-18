import Foundation
import CryptoKit

enum KeyDerivationError: Error {
    case invalidNsec
    case decodeError
}

struct KeyDerivation {

    /// Decode an nsec into a 32-byte Ed25519 seed
    static func decodeNsec(_ nsec: String) throws -> Data {
        if nsec.hasPrefix("nsec1") {
            // Simplified bech32 logic for stubbing, or assume caller provides decoded hex for MVP
            // Normally we'd use a real bech32 library here
            // Let's assume we implement a simple one or fall back to hex.
            throw KeyDerivationError.invalidNsec
        } else {
            return try hexStringToData(nsec)
        }
    }

    /// Returns the hex npub from Ed25519 seed
    static func deriveNpubHex(seed: Data) throws -> String {
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    }

    /// Returns the WireGuard private key from the seed
    static func deriveWGPrivate(seed: Data) -> Data {
        var hasher = SHA256()
        hasher.update(data: "thedarknet-wg-v1".data(using: .utf8)!)
        hasher.update(data: seed)
        return Data(hasher.finalize())
    }

    /// Returns the WireGuard public key from WG private key
    static func deriveWGPublic(wgPrivate: Data) throws -> Data {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: wgPrivate)
        return privateKey.publicKey.rawRepresentation
    }

    /// Returns the IPv6 address from npub hex string
    static func deriveIPv6(npubHex: String) -> String {
        var hasher = SHA256()
        hasher.update(data: "thedarknet-ipv6-v1".data(using: .utf8)!)
        hasher.update(data: npubHex.data(using: .utf8)!)
        let hash = Data(hasher.finalize())

        var ip = [UInt8](repeating: 0, count: 16)
        ip[0] = 0xfd
        ip[1] = 0x00

        for i in 0..<13 {
            ip[2 + i] = hash[i]
        }
        ip[15] = 0x01

        // Format as IPv6 string
        var parts: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            let part = String(format: "%02x%02x", ip[i], ip[i+1])
            parts.append(part.trimmingCharacters(in: CharacterSet(charactersIn: "0")).isEmpty ? "0" : part)
        }

        // Simple formatter, does not compress :: fully but valid enough for iOS NetworkExtension
        let joined = parts.joined(separator: ":")
        return joined.replacingOccurrences(of: ":0:0:0:", with: "::") // simplistic compression
    }

    // Helper to decode hex string
    static func hexStringToData(_ string: String) throws -> Data {
        let len = string.count / 2
        var data = Data(capacity: len)
        var index = string.startIndex
        for _ in 0..<len {
            let nextIndex = string.index(index, offsetBy: 2)
            let bytes = string[index..<nextIndex]
            if let num = UInt8(bytes, radix: 16) {
                data.append(num)
            } else {
                throw KeyDerivationError.decodeError
            }
            index = nextIndex
        }
        return data
    }
}
