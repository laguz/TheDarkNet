import SwiftUI

#if os(macOS)
import AppKit
internal import Combine
#endif

// MARK: - Tunnel model
//
// Dev build: we don't call NETunnelProviderManager because the app isn't
// signed with the `packet-tunnel-provider` entitlement, which makes even
// saveToPreferences() fail with NEConfigurationErrorDomain code 10.
//
// Instead, tunnels live entirely in user-space storage: a JSON blob in
// UserDefaults + a mirror file under ~/Library/Application Support. The UI
// is indistinguishable from an NE-backed build. When you later get the
// entitlement, wire `TunnelViewModel.persist`/`toggle` to NE and delete
// `LocalTunnelStore` — the rest of the code doesn't care.

enum TunnelStatus: String, Codable, Hashable {
    case disconnected
    case connecting
    case connected
    case disconnecting

    var isActive: Bool {
        self == .connected || self == .connecting
    }
}

struct TunnelConfig: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var name: String
    var serverAddress: String
    var nsecSuffix: String        // last 10 chars of the nsec, for display
    var status: TunnelStatus = .disconnected
    var createdAt: Date = .now
}

// MARK: - Status helpers

func statusString(for status: TunnelStatus) -> String {
    switch status {
    case .disconnected:  return "Disconnected"
    case .connecting:    return "Connecting…"
    case .connected:     return "Connected"
    case .disconnecting: return "Disconnecting…"
    }
}

func statusColor(for status: TunnelStatus) -> Color {
    switch status {
    case .connected:    return .green
    case .connecting:   return .yellow
    case .disconnecting: return .orange
    case .disconnected: return Color.secondary.opacity(0.6)
    }
}

// MARK: - Userspace paths + launchd agent (unchanged — still runs under user)

#if os(macOS)
enum UserspacePaths {
    static var home: URL       { FileManager.default.homeDirectoryForCurrentUser }
    static var supportDir: URL { home.appendingPathComponent("Library/Application Support/TheDarkNet") }
    static var binDir: URL     { supportDir.appendingPathComponent("bin") }
    static var logDir: URL     { supportDir.appendingPathComponent("Logs") }
    static var agentsDir: URL  { home.appendingPathComponent("Library/LaunchAgents") }
    static var tunnelsFile: URL { supportDir.appendingPathComponent("tunnels.json") }

    static var agentBinary: URL  { binDir.appendingPathComponent("thedarknet-agent") }
    static var hyperdScript: URL { binDir.appendingPathComponent("hyperd/index.js") }

    static func ensureLayout() throws {
        for dir in [supportDir, binDir, logDir, agentsDir,
                    binDir.appendingPathComponent("hyperd")] {
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true, attributes: nil
            )
        }
    }
}

final class UserspaceAgentController {

    enum AgentError: Error { case missingTemplate(String), launchctlFailed(Int32, String) }

    @discardableResult
    func install() throws -> [String] {
        try UserspacePaths.ensureLayout()
        try copyResourcesIfNeeded()

        let uid = getuid()
        var installed: [String] = []

        for name in ["com.thedarknet.agent", "com.thedarknet.hyperd"] {
            let bundled = URL(fileURLWithPath: Bundle.main.bundlePath)
                .appendingPathComponent("Contents/Library/LaunchAgents/\(name).plist")
            let fallback = Bundle.main.url(forResource: name, withExtension: "plist")
            let src: URL
            if FileManager.default.fileExists(atPath: bundled.path) {
                src = bundled
            } else if let fb = fallback {
                src = fb
            } else {
                throw AgentError.missingTemplate(name)
            }

            let template = try String(contentsOf: src, encoding: .utf8)
            let rendered = template
                .replacingOccurrences(of: "__TDN_HOME__",         with: UserspacePaths.home.path)
                .replacingOccurrences(of: "__TDN_LOG_DIR__",      with: UserspacePaths.logDir.path)
                .replacingOccurrences(of: "__TDN_AGENT_PATH__",   with: UserspacePaths.agentBinary.path)
                .replacingOccurrences(of: "__TDN_NODE_PATH__",    with: resolveNode())
                .replacingOccurrences(of: "__TDN_HYPERD_SCRIPT__", with: UserspacePaths.hyperdScript.path)

            let dest = UserspacePaths.agentsDir.appendingPathComponent("\(name).plist")
            try rendered.write(to: dest, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o644],
                                                  ofItemAtPath: dest.path)

            _ = try? runLaunchctl(["bootout", "gui/\(uid)", dest.path])
            try runLaunchctl(["bootstrap", "gui/\(uid)", dest.path])
            installed.append(name)
        }
        return installed
    }

    func uninstall() {
        let uid = getuid()
        for name in ["com.thedarknet.agent", "com.thedarknet.hyperd"] {
            let plist = UserspacePaths.agentsDir.appendingPathComponent("\(name).plist")
            _ = try? runLaunchctl(["bootout", "gui/\(uid)", plist.path])
            try? FileManager.default.removeItem(at: plist)
        }
    }

    private func copyResourcesIfNeeded() throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: UserspacePaths.agentBinary.path) {
            if let bundled = Bundle.main.url(forResource: "thedarknet-agent", withExtension: nil) {
                try fm.copyItem(at: bundled, to: UserspacePaths.agentBinary)
            } else {
                try "#!/bin/sh\nexec /usr/bin/true\n"
                    .write(to: UserspacePaths.agentBinary, atomically: true, encoding: .utf8)
            }
            try fm.setAttributes([.posixPermissions: 0o755],
                                 ofItemAtPath: UserspacePaths.agentBinary.path)
        }
        if !fm.fileExists(atPath: UserspacePaths.hyperdScript.path) {
            if let bundled = Bundle.main.url(
                forResource: "index", withExtension: "js", subdirectory: "hyperd"
            ) {
                try fm.copyItem(at: bundled, to: UserspacePaths.hyperdScript)
            } else {
                try "// hyperd placeholder — replace with real script\n"
                    .write(to: UserspacePaths.hyperdScript, atomically: true, encoding: .utf8)
            }
        }
    }

    private func resolveNode() -> String {
        for candidate in [
            "\(UserspacePaths.home.path)/.volta/bin/node",
            "\(UserspacePaths.home.path)/.nvm/versions/node/current/bin/node",
            "/opt/homebrew/bin/node",
            "/usr/local/bin/node",
        ] where FileManager.default.isExecutableFile(atPath: candidate) {
            return candidate
        }
        return "/opt/homebrew/bin/node"
    }

    @discardableResult
    private func runLaunchctl(_ args: [String]) throws -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError  = pipe
        try proc.run()
        proc.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(),
                         encoding: .utf8) ?? ""
        if proc.terminationStatus != 0 {
            throw AgentError.launchctlFailed(proc.terminationStatus, out)
        }
        return out
    }
}
#endif

// MARK: - System VPN reader (scutil --nc list)
//
// macOS has no public API to enumerate *all* VPN configurations regardless of
// which app registered them (`NETunnelProviderManager.loadAllFromPreferences`
// is scoped to the current app's bundle id, and needs the NetworkExtension
// entitlement). `scutil --nc list` is the shell-accessible equivalent the
// system ships — it prints every network connection service, including VPNs
// created by other apps and the built-in System Settings > VPN panel.
//
// We don't try to start/stop them — that would need the tunnel's owning app —
// but we do show them in the UI so you can confirm they still exist.

struct SystemVPN: Identifiable, Hashable {
    let id: String            // UUID reported by scutil
    let name: String
    let kind: String          // IPSec, PPP, L2TP, IKEv2, com.apple.<provider>, etc.
    let connected: Bool
}

#if os(macOS)
enum SystemVPNReader {

    /// Runs `/usr/sbin/scutil --nc list` and parses each row.
    static func list() -> [SystemVPN] {
        guard let output = runScutil(["--nc", "list"]) else { return [] }
        return parse(output)
    }

    /// Parses output like:
    /// ```
    /// Available network connections
    /// * (Disconnected)   0E12A987-...-DEF012345678 IPSec       "Work VPN"     [Local]
    ///   (Connected)     ABCDEF12-... L2TP        "Home VPN"
    /// ```
    static func parse(_ output: String) -> [SystemVPN] {
        var result: [SystemVPN] = []
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty,
                  line != "Available network connections",
                  let paren = line.firstIndex(of: "("),
                  let parenEnd = line.firstIndex(of: ")") else { continue }

            let status = String(line[line.index(after: paren)..<parenEnd])
            let rest = line[line.index(after: parenEnd)...]
                .trimmingCharacters(in: .whitespaces)

            // Tokens: <UUID> <Kind> "Name" [extras]
            let tokens = rest.split(separator: " ", maxSplits: 2,
                                    omittingEmptySubsequences: true)
            guard tokens.count >= 3 else { continue }

            let uuid = String(tokens[0])
            let kind = String(tokens[1])
            // The remainder starts with `"name"` possibly followed by [Local] etc.
            let remainder = String(tokens[2])
            let name = extractQuoted(remainder) ?? remainder

            result.append(SystemVPN(
                id: uuid,
                name: name,
                kind: kind,
                connected: status.lowercased().contains("connected") &&
                           !status.lowercased().contains("dis")
            ))
        }
        return result
    }

    private static func extractQuoted(_ s: String) -> String? {
        guard let first = s.firstIndex(of: "\""),
              let last  = s[s.index(after: first)...].firstIndex(of: "\"")
        else { return nil }
        return String(s[s.index(after: first)..<last])
    }

    private static func runScutil(_ args: [String]) -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError  = Pipe()  // swallow stderr
        do { try proc.run() } catch { return nil }
        proc.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(),
                      encoding: .utf8)
    }
}
#endif

// MARK: - Local tunnel storage (UserDefaults + JSON mirror on disk)

final class LocalTunnelStore {
    private let defaultsKey = "com.thedarknet.tunnels.v1"

    func load() -> [TunnelConfig] {
        if let data = UserDefaults.standard.data(forKey: defaultsKey),
           let decoded = try? JSONDecoder().decode([TunnelConfig].self, from: data) {
            return decoded
        }
        #if os(macOS)
        if let disk = try? Data(contentsOf: UserspacePaths.tunnelsFile),
           let decoded = try? JSONDecoder().decode([TunnelConfig].self, from: disk) {
            return decoded
        }
        #endif
        return []
    }

    func save(_ tunnels: [TunnelConfig]) {
        guard let data = try? JSONEncoder().encode(tunnels) else { return }
        UserDefaults.standard.set(data, forKey: defaultsKey)

        #if os(macOS)
        do {
            try UserspacePaths.ensureLayout()
            try data.write(to: UserspacePaths.tunnelsFile, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: UserspacePaths.tunnelsFile.path
            )
        } catch {
            // Best-effort — the UserDefaults copy is authoritative.
        }
        #endif
    }
}

// MARK: - View model

final class TunnelViewModel: ObservableObject {
    @Published var tunnels: [TunnelConfig] = []
    @Published var systemVPNs: [SystemVPN] = []
    @Published var lastError: String?
    @Published var toolchainAvailable: Bool = false

    private let store = LocalTunnelStore()

    #if os(macOS)
    private let runner = WireGuardRunner()
    #endif

    init() {
        self.tunnels = store.load()
        #if os(macOS)
        self.toolchainAvailable = WireGuardRunner.toolchainAvailable
        #endif
        refreshSystemVPNs()
    }

    func refreshSystemVPNs() {
        #if os(macOS)
        // scutil is fast but still I/O — kick off async so we don't block init.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let list = SystemVPNReader.list()
            DispatchQueue.main.async { self?.systemVPNs = list }
        }
        #endif
    }

    // MARK: create

    /// Accept a pasted nsec, derive real WireGuard keys from it, persist the
    /// nsec into the user keychain keyed by this tunnel's UUID, write a
    /// wg-quick config, and (on macOS with the toolchain installed)
    /// immediately bring the interface up. An admin password prompt appears
    /// once when `wg-quick up` is invoked; cancelling it is a soft failure.
    func createTunnel(nsec: String) {
        let trimmed = nsec.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            lastError = "Please enter an nsec"
            return
        }

        let suffix = String(trimmed.suffix(10))
        let name   = "TheDarkNet – \(suffix)"

        // De-dup: if a tunnel with this suffix already exists, surface it
        // instead of appending a second copy.
        if tunnels.contains(where: { $0.nsecSuffix == suffix }) {
            lastError = "A tunnel for this key already exists"
            return
        }

        // Derive real IPv6 up front so the row can display it immediately.
        var address = "fd00::/8 (pending)"
        #if os(macOS)
        if let keys = try? WireGuardRunner.deriveKeys(fromNsec: trimmed) {
            address = keys.ipv6
        }
        #endif

        var config = TunnelConfig(
            name: name,
            serverAddress: address,
            nsecSuffix: suffix
        )

        #if os(macOS)
        // If the toolchain is present, try to bring the tunnel up right now.
        // Anything that goes wrong becomes a soft error on the row; the
        // tunnel still lands in storage so the user can retry from the toggle.
        if WireGuardRunner.toolchainAvailable {
            config.status = .connecting
            persistNsec(trimmed, for: config.id)
            tunnels.append(config)
            store.save(tunnels)

            let tunnelForUp = config
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self = self else { return }
                do {
                    let ipv6 = try self.runner.up(tunnelForUp, nsec: trimmed)
                    DispatchQueue.main.async {
                        guard let idx = self.tunnels.firstIndex(where: { $0.id == tunnelForUp.id })
                        else { return }
                        self.tunnels[idx].serverAddress = ipv6
                        self.tunnels[idx].status = .connected
                        self.store.save(self.tunnels)
                    }
                } catch {
                    DispatchQueue.main.async {
                        guard let idx = self.tunnels.firstIndex(where: { $0.id == tunnelForUp.id })
                        else { return }
                        self.tunnels[idx].status = .disconnected
                        self.store.save(self.tunnels)
                        self.lastError = Self.describe(error)
                    }
                }
            }
            return
        }
        #endif

        // No toolchain (or non-macOS build): keep the tunnel in storage so
        // the user sees it, and surface a hint.
        persistNsec(trimmed, for: config.id)
        tunnels.append(config)
        store.save(tunnels)
        #if os(macOS)
        lastError = "Tunnel saved. Install the userspace toolchain to bring it up: \(WireGuardRunner.installHint)"
        #endif
    }

    // MARK: toggle / rename / delete

    func toggle(_ id: UUID) {
        guard let idx = tunnels.firstIndex(where: { $0.id == id }) else { return }
        let current = tunnels[idx]

        switch current.status {
        case .disconnected:
            bringUp(current)
        case .connected, .connecting:
            bringDown(current)
        case .disconnecting:
            break
        }
    }

    func rename(_ id: UUID, to newName: String) {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let idx = tunnels.firstIndex(where: { $0.id == id }) else { return }
        tunnels[idx].name = trimmed
        store.save(tunnels)
    }

    func delete(_ id: UUID) {
        guard let idx = tunnels.firstIndex(where: { $0.id == id }) else { return }
        let tunnel = tunnels[idx]

        // Best-effort bring-down if the tunnel is live. We don't wait on it —
        // the user already decided it should be gone.
        #if os(macOS)
        if tunnel.status.isActive, WireGuardRunner.toolchainAvailable {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                try? self?.runner.down(tunnel)
            }
        }
        let configURL = WireGuardRunner.configPath(for: tunnel)
        try? FileManager.default.removeItem(at: configURL)
        #endif

        // Scrub the keychain entry for this tunnel specifically.
        let delQuery: [String: Any] = [
            kSecClass       as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.thedarknet.nsec",
            kSecAttrAccount as String: id.uuidString,
        ]
        SecItemDelete(delQuery as CFDictionary)

        tunnels.remove(at: idx)
        store.save(tunnels)
    }

    func reload() {
        tunnels = store.load()
        refreshSystemVPNs()
    }

    // MARK: up / down (async wrappers around WireGuardRunner)

    #if os(macOS)
    private func bringUp(_ tunnel: TunnelConfig) {
        guard WireGuardRunner.toolchainAvailable else {
            lastError = "Userspace toolchain missing. Run: \(WireGuardRunner.installHint)"
            return
        }
        guard let nsec = fetchNsec(for: tunnel.id) else {
            lastError = "No nsec stored for this tunnel. Delete and re-add it."
            return
        }

        updateStatus(tunnel.id, to: .connecting)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            do {
                let ipv6 = try self.runner.up(tunnel, nsec: nsec)
                DispatchQueue.main.async {
                    guard let idx = self.tunnels.firstIndex(where: { $0.id == tunnel.id })
                    else { return }
                    self.tunnels[idx].serverAddress = ipv6
                    self.tunnels[idx].status = .connected
                    self.store.save(self.tunnels)
                }
            } catch {
                DispatchQueue.main.async {
                    self.updateStatus(tunnel.id, to: .disconnected)
                    self.lastError = Self.describe(error)
                }
            }
        }
    }

    private func bringDown(_ tunnel: TunnelConfig) {
        guard WireGuardRunner.toolchainAvailable else {
            // Without the toolchain we can't really tear it down — just flip
            // the UI state so the user isn't stuck on a stale "Connected".
            updateStatus(tunnel.id, to: .disconnected)
            return
        }

        updateStatus(tunnel.id, to: .disconnecting)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            do {
                try self.runner.down(tunnel)
                DispatchQueue.main.async {
                    self.updateStatus(tunnel.id, to: .disconnected)
                }
            } catch {
                DispatchQueue.main.async {
                    // Leave the row in its previous active state so the user
                    // can retry; surface the error so they know why.
                    self.updateStatus(tunnel.id, to: .connected)
                    self.lastError = Self.describe(error)
                }
            }
        }
    }
    #else
    private func bringUp(_ tunnel: TunnelConfig)   { updateStatus(tunnel.id, to: .connected) }
    private func bringDown(_ tunnel: TunnelConfig) { updateStatus(tunnel.id, to: .disconnected) }
    #endif

    private func updateStatus(_ id: UUID, to status: TunnelStatus) {
        guard let idx = tunnels.firstIndex(where: { $0.id == id }) else { return }
        tunnels[idx].status = status
        store.save(tunnels)
    }

    // MARK: nsec keychain (per-tunnel, plus best-effort ~/Library copy)

    /// Keychain service stays fixed ("com.thedarknet.nsec") and we key by the
    /// tunnel UUID. A single `~/Library/Application Support/TheDarkNet/nsec`
    /// file still exists for downstream tooling (hyperd, agent) that reads
    /// "the" nsec — the most recently-added tunnel wins there, which matches
    /// the single-identity assumption of those scripts.
    private func persistNsec(_ nsec: String, for tunnelId: UUID) {
        let query: [String: Any] = [
            kSecClass       as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.thedarknet.nsec",
            kSecAttrAccount as String: tunnelId.uuidString,
            kSecValueData   as String: Data(nsec.utf8),
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)

        #if os(macOS)
        do {
            try UserspacePaths.ensureLayout()
            let nsecURL = UserspacePaths.supportDir.appendingPathComponent("nsec")
            try nsec.write(to: nsecURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: nsecURL.path
            )
        } catch {
            lastError = "Couldn't write nsec: \(error.localizedDescription)"
        }
        #endif
    }

    private func fetchNsec(for tunnelId: UUID) -> String? {
        let query: [String: Any] = [
            kSecClass       as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.thedarknet.nsec",
            kSecAttrAccount as String: tunnelId.uuidString,
            kSecReturnData  as String: true,
            kSecMatchLimit  as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let str = String(data: data, encoding: .utf8)
        else { return nil }
        return str
    }

    // MARK: error formatting

    private static func describe(_ error: Error) -> String {
        if let e = error as? LocalizedError, let msg = e.errorDescription {
            return msg
        }
        return String(describing: error)
    }
}

// MARK: - Root view

struct ContentView: View {
    @StateObject private var vm = TunnelViewModel()
    @State private var nsecInput: String = ""
    @State private var showingAdd = false

    #if os(macOS)
    private let agent = UserspaceAgentController()
    #endif

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            devBanner
            Divider().padding(.bottom, 4)

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    section(title: "Your tunnels",
                            subtitle: vm.tunnels.isEmpty ? "No tunnels yet" : nil) {
                        if vm.tunnels.isEmpty {
                            emptyLocal
                        } else {
                            localList
                        }
                    }

                    section(title: "System VPNs",
                            subtitle: vm.systemVPNs.isEmpty
                                        ? "None configured in System Settings"
                                        : "\(vm.systemVPNs.count) configured on this Mac") {
                        if !vm.systemVPNs.isEmpty {
                            systemList
                        }
                    }
                }
                .padding(.bottom, 12)
            }

            if let err = vm.lastError {
                Text(err)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(.horizontal)
                    .padding(.vertical, 6)
            }
        }
        .frame(minWidth: 460, minHeight: 420)
        .background(Color(nsColor: .windowBackgroundColor))
        .sheet(isPresented: $showingAdd) { addTunnelSheet }
    }

    // MARK: section wrapper

    @ViewBuilder
    private func section<Content: View>(
        title: String,
        subtitle: String?,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(title)
                    .font(.subheadline).fontWeight(.semibold)
                if let subtitle = subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 14)
            content()
        }
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.shield.fill")
                .font(.title2)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text("TheDarkNet")
                    .font(.headline)
                Text(vm.tunnels.isEmpty
                     ? "No tunnels yet"
                     : "\(vm.tunnels.count) tunnel\(vm.tunnels.count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
            Button { vm.reload() } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("Reload from disk")

            Button {
                nsecInput = ""
                showingAdd = true
            } label: {
                Label("Add", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
        }
        .padding(14)
    }

    // MARK: toolchain banner
    //
    // Live status strip under the header. Green when wireguard-tools is on
    // disk (real tunnels will come up on paste, behind one admin prompt);
    // orange when it isn't, with the exact brew command to fix it.

    private var devBanner: some View {
        HStack(spacing: 8) {
            #if os(macOS)
            if vm.toolchainAvailable {
                Image(systemName: "checkmark.seal.fill")
                    .foregroundColor(.green)
                Text("wireguard-go ready · admin prompt on connect")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
                Text("Missing userspace toolchain · run `\(WireGuardRunner.installHint)`")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer(minLength: 6)
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(WireGuardRunner.installHint,
                                                    forType: .string)
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
            }
            #else
            Image(systemName: "wrench.and.screwdriver")
                .foregroundColor(.orange)
            Text("Dev mode")
                .font(.caption)
                .foregroundColor(.secondary)
            #endif
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        .background(
            (vm.toolchainAvailable ? Color.green : Color.orange).opacity(0.10)
        )
    }

    // MARK: local tunnels list

    private var localList: some View {
        LazyVStack(spacing: 0) {
            ForEach(vm.tunnels.indices, id: \.self) { idx in
                TunnelRow(config: vm.tunnels[idx], vm: vm)
                if idx < vm.tunnels.count - 1 {
                    Divider().padding(.leading, 44)
                }
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .padding(.horizontal, 14)
    }

    private var emptyLocal: some View {
        HStack {
            Spacer()
            VStack(spacing: 8) {
                Image(systemName: "network.slash")
                    .font(.system(size: 24))
                    .foregroundColor(.secondary)
                Text("No tunnels configured")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Button("Add a tunnel") {
                    nsecInput = ""
                    showingAdd = true
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
            Spacer()
        }
        .padding(.vertical, 24)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.6))
        )
        .padding(.horizontal, 14)
    }

    // MARK: system VPNs list

    private var systemList: some View {
        LazyVStack(spacing: 0) {
            ForEach(Array(vm.systemVPNs.enumerated()), id: \.element.id) { idx, svc in
                SystemVPNRow(service: svc)
                if idx < vm.systemVPNs.count - 1 {
                    Divider().padding(.leading, 44)
                }
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .padding(.horizontal, 14)
    }

    // MARK: add sheet

    private var addTunnelSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add Tunnel")
                .font(.title3).bold()
            Text("Paste your nsec. Keys are derived locally; the nsec is stored in your user keychain (scoped to this tunnel).")
                .font(.caption)
                .foregroundColor(.secondary)
            #if os(macOS)
            if vm.toolchainAvailable {
                Label("macOS will prompt for your admin password once to start the tunnel.",
                      systemImage: "lock.shield")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            } else {
                Label("Userspace toolchain missing — the tunnel will be saved but not started. Install with: \(WireGuardRunner.installHint)",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption2)
                    .foregroundColor(.orange)
            }
            #endif
            SecureField("nsec1…", text: $nsecInput)
                .textFieldStyle(RoundedBorderTextFieldStyle())

            HStack {
                Spacer()
                Button("Cancel") { showingAdd = false }
                Button("Create") {
                    vm.createTunnel(nsec: nsecInput)
                    if vm.lastError == nil {
                        showingAdd = false
                        #if os(macOS)
                        do { try agent.install() }
                        catch { vm.lastError = "Agent install: \(error)" }
                        #endif
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(nsecInput.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 440)
    }
}

// MARK: - One row, Tailscale style

struct TunnelRow: View {
    let config: TunnelConfig
    @ObservedObject var vm: TunnelViewModel

    @State private var isRenaming = false
    @State private var draftName = ""
    @State private var confirmingDelete = false

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(statusColor(for: config.status))
                .frame(width: 10, height: 10)
                .overlay(Circle().stroke(Color.black.opacity(0.08), lineWidth: 0.5))

            VStack(alignment: .leading, spacing: 2) {
                Text(config.name)
                    .font(.system(.body, design: .rounded))
                    .fontWeight(.medium)
                HStack(spacing: 6) {
                    Text(statusString(for: config.status))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text("·").foregroundColor(.secondary).font(.caption)
                    Text(config.serverAddress)
                        .font(.caption.monospaced())
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            Toggle("", isOn: Binding(
                get: { config.status.isActive },
                set: { _ in vm.toggle(config.id) }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .disabled(config.status == .disconnecting)

            Menu {
                Button("Rename…") {
                    draftName = config.name
                    isRenaming = true
                }
                Button("Copy address") { copyAddress() }
                Divider()
                Button("Delete", role: .destructive) {
                    confirmingDelete = true
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 24, height: 24)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .alert("Rename tunnel", isPresented: $isRenaming) {
            TextField("Name", text: $draftName)
            Button("Save") { vm.rename(config.id, to: draftName) }
            Button("Cancel", role: .cancel) { }
        }
        .alert("Delete this tunnel?", isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive) { vm.delete(config.id) }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Removes the tunnel from your local list. Your keychain entry is preserved.")
        }
    }

    private func copyAddress() {
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(config.serverAddress, forType: .string)
        #endif
    }
}

// MARK: - System VPN row (read-only)

struct SystemVPNRow: View {
    let service: SystemVPN

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(service.connected ? Color.green : Color.secondary.opacity(0.6))
                .frame(width: 10, height: 10)
                .overlay(Circle().stroke(Color.black.opacity(0.08), lineWidth: 0.5))

            VStack(alignment: .leading, spacing: 2) {
                Text(service.name)
                    .font(.system(.body, design: .rounded))
                    .fontWeight(.medium)
                HStack(spacing: 6) {
                    Text(service.connected ? "Connected" : "Disconnected")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text("·").font(.caption).foregroundColor(.secondary)
                    Text(service.kind)
                        .font(.caption.monospaced())
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            Menu {
                Button("Copy UUID") {
                    #if os(macOS)
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(service.id, forType: .string)
                    #endif
                }
                Button("Open Network Settings") {
                    #if os(macOS)
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.network") {
                        NSWorkspace.shared.open(url)
                    }
                    #endif
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 24, height: 24)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}
