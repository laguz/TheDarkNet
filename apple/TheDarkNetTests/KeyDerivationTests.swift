import XCTest
@testable import TheDarkNet

final class KeyDerivationTests: XCTestCase {
    func testKeyDerivations() throws {
        // Fixed nsec for testing: 32 bytes of 0x01
        let seed = Data(repeating: 1, count: 32)

        let npubHex = try KeyDerivation.deriveNpubHex(seed: seed)
        XCTAssertFalse(npubHex.isEmpty, "Npub should not be empty")

        let wgPriv = KeyDerivation.deriveWGPrivate(seed: seed)
        XCTAssertEqual(wgPriv.count, 32, "WG private key should be 32 bytes")

        let wgPub = try KeyDerivation.deriveWGPublic(wgPrivate: wgPriv)
        XCTAssertEqual(wgPub.count, 32, "WG public key should be 32 bytes")

        let ipv6 = KeyDerivation.deriveIPv6(npubHex: npubHex)
        XCTAssertTrue(ipv6.hasPrefix("fd00:"), "IPv6 should be in ULA range fd00::/8")
        XCTAssertTrue(ipv6.hasSuffix(":1") || ipv6.hasSuffix(":01"), "IPv6 should end with 1")
    }
}
