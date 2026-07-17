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
            let (hrp, data) = try Bech32.decode(nsec)
            if hrp != "nsec" {
                throw KeyDerivationError.invalidNsec
            }
            return try Bech32.convertBits(data: data, fromBits: 5, toBits: 8, pad: false)
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
                data.append(&num, count: 1)
            } else {
                throw KeyDerivationError.decodeError
            }
            index = nextIndex
        }
        return data
    }
}

private struct Bech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    private static let generator: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

    static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ UInt32(v)
            for i in 0..<5 {
                if (top >> i) & 1 != 0 {
                    chk ^= generator[i]
                }
            }
        }
        return chk
    }

    static func hrpExpand(_ hrp: String) -> [UInt8] {
        var ret: [UInt8] = []
        for c in hrp.utf8 {
            ret.append(c >> 5)
        }
        ret.append(0)
        for c in hrp.utf8 {
            ret.append(c & 31)
        }
        return ret
    }

    static func verifyChecksum(hrp: String, data: [UInt8]) -> Bool {
        return polymod(hrpExpand(hrp) + data) == 1
    }

    static func decode(_ bechString: String) throws -> (hrp: String, data: [UInt8]) {
        let lower = bechString.lowercased()
        guard let pos = lower.lastIndex(of: "1") else { throw KeyDerivationError.decodeError }
        let hrp = String(lower[..<pos])
        let dataStr = lower[lower.index(after: pos)...]

        var data: [UInt8] = []
        for c in dataStr {
            guard let idx = charset.firstIndex(of: c) else { throw KeyDerivationError.decodeError }
            data.append(UInt8(idx))
        }
        guard verifyChecksum(hrp: hrp, data: data) else { throw KeyDerivationError.decodeError }
        return (hrp, Array(data.dropLast(6)))
    }

    static func convertBits(data: [UInt8], fromBits: Int, toBits: Int, pad: Bool) throws -> Data {
        var acc: Int = 0
        var bits: Int = 0
        let maxv: Int = (1 << toBits) - 1
        let maxAcc: Int = (1 << (fromBits + toBits - 1)) - 1
        var out = Data()

        for value in data {
            let v = Int(value)
            if v < 0 || (v >> fromBits) != 0 {
                throw KeyDerivationError.decodeError
            }
            acc = ((acc << fromBits) | v) & maxAcc
            bits += fromBits
            while bits >= toBits {
                bits -= toBits
                out.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 {
                out.append(UInt8((acc << (toBits - bits)) & maxv))
            }
        } else if bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0 {
            throw KeyDerivationError.decodeError
        }
        return out
    }
}
