import Foundation
import CryptoKit

#if os(macOS)

// MARK: - Errors

enum WireGuardError: LocalizedError {
    case wgQuickNotFound
    case adminCanceled
    case commandFailed(Int32, String)

    var errorDescription: String? {
        switch self {
        case .wgQuickNotFound:
            return "wireguard-tools not found. Install with: brew install wireguard-tools"
        case .adminCanceled:
            return "Admin permission denied"
        case .commandFailed(let code, let msg):
            let trimmed = msg.trimmingCharacters(in: .whitespacesAndNewlines)
            return "wg-quick failed (exit \(code)): \(trimmed.isEmpty ? "no output" : trimmed)"
        }
    }
}

// MARK: - Runner
//
// Userspace tunnel path — no NetworkExtension, no entitlement.
// Uses the Homebrew-installed `wireguard-tools` (which ships `wg-quick` and
// bundles `wireguard-go` under the hood). Each tunnel has its own config
// file at ~/Library/Application Support/TheDarkNet/configs/tdn-<suffix>.conf
// (mode 0600). `wg-quick up <path>` is executed as root via `osascript` so
// the system auth dialog prompts once per action; cancelling the prompt is
// surfaced as `.adminCanceled` rather than a hard failure.

final class WireGuardRunner {

    // MARK: tool discovery

    static func locateWgQuick() -> String? {
        locate("wg-quick")
    }

    static func locateWg() -> String? {
        locate("wg")
    }

    /// True iff both wg-quick and wg are on disk. That's enough for up/down.
    /// (wg-quick internally invokes wireguard-go on macOS, which ships with
    /// the same Homebrew package, so if wg-quick is present wireguard-go is
    /// effectively guaranteed.)
    static var toolchainAvailable: Bool {
        locateWgQuick() != nil && locateWg() != nil
    }

    /// Single place to tell the user how to install the toolchain.
    static let installHint = "brew install wireguard-tools"

    private static func locate(_ bin: String) -> String? {
        let candidates = [
            "/opt/homebrew/bin/\(bin)",
            "/usr/local/bin/\(bin)",
            "\(NSHomeDirectory())/.local/bin/\(bin)",
            "/usr/bin/\(bin)",
        ]
        for p in candidates where FileManager.default.isExecutableFile(atPath: p) {
            return p
        }
        return nil
    }

    // MARK: config file layout

    private static var configsDir: URL {
        UserspacePaths.supportDir.appendingPathComponent("configs")
    }

    static func configPath(for tunnel: TunnelConfig) -> URL {
        // `wg-quick` uses the file's basename as the logical interface name
        // in its state tracking; we pick a stable, filesystem-safe name.
        let safeSuffix = tunnel.nsecSuffix
            .replacingOccurrences(of: "/", with: "_")
            .prefix(24)
        return configsDir.appendingPathComponent("tdn-\(safeSuffix).conf")
    }

    // MARK: key derivation

    struct WireGuardKeys {
        let privateKeyB64: String
        let publicKeyB64: String
        let ipv6: String
    }

    /// Derive a deterministic WG keypair + IPv6 from the pasted nsec. Accepts
    /// raw-hex seeds (handled by `KeyDerivation.decodeNsec`); for bech32
    /// `nsec1…` input we fall back to `SHA256(nsec)` since there's no bech32
    /// decoder in-tree. Same nsec → same keys → same IPv6 every run.
    static func deriveKeys(fromNsec nsec: String) throws -> WireGuardKeys {
        let seed: Data
        if let hex = try? KeyDerivation.decodeNsec(nsec) {
            seed = hex
        } else {
            seed = Data(SHA256.hash(data: Data(nsec.utf8)))
        }

        let wgPriv = KeyDerivation.deriveWGPrivate(seed: seed)
        let wgPub  = try KeyDerivation.deriveWGPublic(wgPrivate: wgPriv)
        let pubHex = wgPub.map { String(format: "%02x", $0) }.joined()
        let ipv6   = KeyDerivation.deriveIPv6(npubHex: pubHex)

        return WireGuardKeys(
            privateKeyB64: wgPriv.base64EncodedString(),
            publicKeyB64:  wgPub.base64EncodedString(),
            ipv6: ipv6
        )
    }

    // MARK: config file

    @discardableResult
    static func writeConfig(
        for tunnel: TunnelConfig,
        keys: WireGuardKeys
    ) throws -> URL {
        try FileManager.default.createDirectory(
            at: configsDir, withIntermediateDirectories: true
        )
        let url = configPath(for: tunnel)

        let iso = ISO8601DateFormatter().string(from: Date())
        let config = """
        # TheDarkNet · \(tunnel.name)
        # Generated \(iso)
        #
        # PublicKey = \(keys.publicKeyB64)
        # IPv6      = \(keys.ipv6)
        #
        # Peers are added dynamically by the agent/hyperd once the interface
        # is up (`wg set <iface> peer <pubkey> allowed-ips <cidr> endpoint <host:port>`).

        [Interface]
        PrivateKey = \(keys.privateKeyB64)
        Address = \(keys.ipv6)/128
        MTU = 1280
        """
        try config.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url.path
        )
        return url
    }

    // MARK: up / down

    /// Bring tunnel up. Returns the derived IPv6 so the caller can stash it
    /// in its TunnelConfig. Throws `.adminCanceled` if the user dismisses
    /// the auth dialog — treat that as a soft failure, not a crash.
    @discardableResult
    func up(_ tunnel: TunnelConfig, nsec: String) throws -> String {
        guard let wgQuick = Self.locateWgQuick() else {
            throw WireGuardError.wgQuickNotFound
        }

        let keys = try Self.deriveKeys(fromNsec: nsec)
        let configURL = try Self.writeConfig(for: tunnel, keys: keys)

        try runAsAdmin(
            command: "\(shellQuote(wgQuick)) up \(shellQuote(configURL.path))",
            prompt: "TheDarkNet wants to start the tunnel \(tunnel.name)."
        )

        return keys.ipv6
    }

    /// Bring tunnel down. Missing config file is non-fatal — the tunnel may
    /// have been removed externally.
    func down(_ tunnel: TunnelConfig) throws {
        guard let wgQuick = Self.locateWgQuick() else {
            throw WireGuardError.wgQuickNotFound
        }
        let configURL = Self.configPath(for: tunnel)
        guard FileManager.default.fileExists(atPath: configURL.path) else {
            return
        }

        try runAsAdmin(
            command: "\(shellQuote(wgQuick)) down \(shellQuote(configURL.path))",
            prompt: "TheDarkNet wants to stop the tunnel \(tunnel.name)."
        )
    }

    // MARK: helpers

    private func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Runs `do shell script "..." with administrator privileges`. The auth
    /// dialog appears on the user's desktop; dismissing it with Cancel yields
    /// a -128 / "User canceled" from osascript, which we translate.
    private func runAsAdmin(command: String, prompt: String) throws {
        let escapedCommand = command
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let escapedPrompt = prompt
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = """
        do shell script "\(escapedCommand)" \
        with administrator privileges \
        with prompt "\(escapedPrompt)"
        """

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError  = errPipe

        try proc.run()
        proc.waitUntilExit()

        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(),
                         encoding: .utf8) ?? ""
        let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(),
                         encoding: .utf8) ?? ""

        if proc.terminationStatus != 0 {
            if err.contains("User canceled") || err.contains("(-128)") {
                throw WireGuardError.adminCanceled
            }
            throw WireGuardError.commandFailed(
                proc.terminationStatus,
                err.isEmpty ? out : err
            )
        }
    }
}

#endif
