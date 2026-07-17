import NetworkExtension
import Foundation
import Network
import CryptoKit
import WireGuardKit

class PacketTunnelProvider: NEPacketTunnelProvider {

    private lazy var adapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self) { logLevel, message in
            NSLog("WireGuardAdapter [\(logLevel)]: \(message)")
        }
    }()

    private var pollTimer: DispatchSourceTimer?
    private var tunnelConfig: TunnelConfiguration?
    private var currentConnection: NWConnection?

    private let workQueue = DispatchQueue(label: "com.thedarknet.hyperd.poll", qos: .background)

    struct PeerInfo: Codable {
        let npub: String
        let endpoint: String
    }

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let supportDir = URL(fileURLWithPath: "\(NSHomeDirectory())/Library/Application Support/TheDarkNet")
        let nsecPath = supportDir.appendingPathComponent("nsec")

        guard let nsec = try? String(contentsOf: nsecPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) else {
            completionHandler(NSError(domain: "PacketTunnelProvider", code: 1, userInfo: [NSLocalizedDescriptionKey: "nsec not found"]))
            return
        }

        let seed: Data
        do {
            seed = try KeyDerivation.decodeNsec(nsec)
        } catch {
            seed = Data(SHA256.hash(data: Data(nsec.utf8)))
        }

        let wgPrivData = KeyDerivation.deriveWGPrivate(seed: seed)
        guard let wgPriv = PrivateKey(rawData: wgPrivData) else {
            completionHandler(NSError(domain: "PacketTunnelProvider", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid WG private key"]))
            return
        }

        guard let wgPubData = try? KeyDerivation.deriveWGPublic(wgPrivate: wgPrivData),
              let pubHex = Optional(wgPubData.map { String(format: "%02x", $0) }.joined()) else {
            completionHandler(NSError(domain: "PacketTunnelProvider", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid WG public key"]))
            return
        }

        let ipv6 = KeyDerivation.deriveIPv6(npubHex: pubHex)

        var interfaceConfig = InterfaceConfiguration(privateKey: wgPriv)
        if let addr = IPv6Address(ipv6) {
            interfaceConfig.addresses = [IPAddressRange(address: addr, networkPrefixLength: 128)]
        }
        interfaceConfig.mtu = 1280

        let initialConfig = TunnelConfiguration(name: "TheDarkNet", interface: interfaceConfig, peers: [])
        self.tunnelConfig = initialConfig

        adapter.start(tunnelConfiguration: initialConfig) { error in
            if let error = error {
                completionHandler(error)
            } else {
                self.startPolling()
                completionHandler(nil)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pollTimer?.cancel()
        currentConnection?.cancel()
        currentConnection = nil
        adapter.stop { _ in
            completionHandler()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let handler = completionHandler {
            handler(messageData)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
    }

    private func startPolling() {
        let timer = DispatchSource.makeTimerSource(queue: workQueue)
        timer.schedule(deadline: .now(), repeating: 10.0)
        timer.setEventHandler { [weak self] in
            self?.pollHyperd()
        }
        timer.resume()
        self.pollTimer = timer
    }

    private func pollHyperd() {
        // Cancel any pending connection
        currentConnection?.cancel()

        let sockPath = "\(NSHomeDirectory())/Library/Application Support/TheDarkNet/hyperd.sock"
        let endpoint = NWEndpoint.unix(path: sockPath)
        let connection = NWConnection(to: endpoint, using: .tcp)
        self.currentConnection = connection

        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let connection = connection else { return }
            switch state {
            case .ready:
                let msg = "get-peers\n".data(using: .utf8)!
                connection.send(content: msg, completion: .contentProcessed({ error in
                    if error == nil {
                        self?.readResponse(from: connection, data: Data())
                    } else {
                        connection.cancel()
                        if self?.currentConnection === connection {
                            self?.currentConnection = nil
                        }
                    }
                }))
            case .failed(_), .cancelled:
                connection.cancel()
                if self?.currentConnection === connection {
                    self?.currentConnection = nil
                }
            default:
                break
            }
        }
        connection.start(queue: workQueue)
    }

    private func readResponse(from connection: NWConnection, data: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self, weak connection] content, context, isComplete, error in
            guard let connection = connection else { return }
            var mutableData = data

            if let content = content {
                mutableData.append(content)
            }

            if let range = mutableData.range(of: Data("\n".utf8)) {
                let messageData = mutableData.prefix(upTo: range.lowerBound)
                if let peersInfo = try? JSONDecoder().decode([PeerInfo].self, from: messageData) {
                    self?.updatePeers(peersInfo: peersInfo)
                }
                connection.cancel()
                if self?.currentConnection === connection {
                    self?.currentConnection = nil
                }
                return
            }

            if error != nil || isComplete {
                connection.cancel()
                if self?.currentConnection === connection {
                    self?.currentConnection = nil
                }
                return
            }

            self?.readResponse(from: connection, data: mutableData)
        }
    }

    private func updatePeers(peersInfo: [PeerInfo]) {
        guard let currentConfig = self.tunnelConfig else { return }

        var peers: [PeerConfiguration] = []
        for info in peersInfo {
            // Hex pubkey to Data
            var pubData = Data()
            var index = info.npub.startIndex
            while index < info.npub.endIndex {
                let next = info.npub.index(index, offsetBy: 2)
                if next <= info.npub.endIndex, let byte = UInt8(info.npub[index..<next], radix: 16) {
                    pubData.append(byte)
                }
                index = next
            }

            guard let pubKey = PublicKey(rawData: pubData) else { continue }

            var peer = PeerConfiguration(publicKey: pubKey)

            // Endpoint parsing handling IPv6
            var endpointString = info.endpoint
            var portString = ""
            var hostString = ""

            if endpointString.hasPrefix("["), let closingBracket = endpointString.lastIndex(of: "]") {
                hostString = String(endpointString[endpointString.index(after: endpointString.startIndex)..<closingBracket])
                let afterBracket = endpointString.index(after: closingBracket)
                if afterBracket < endpointString.endIndex, endpointString[afterBracket] == ":" {
                    portString = String(endpointString[endpointString.index(after: afterBracket)...])
                }
            } else if let colonIndex = endpointString.lastIndex(of: ":") {
                hostString = String(endpointString[..<colonIndex])
                portString = String(endpointString[endpointString.index(after: colonIndex)...])
            }

            if let portNum = UInt16(portString), let port = NWEndpoint.Port(rawValue: portNum) {
                let endpoint: Endpoint
                if let ipv4 = IPv4Address(hostString) {
                    endpoint = Endpoint(host: .ipv4(ipv4), port: port)
                    peer.endpoint = endpoint
                } else if let ipv6 = IPv6Address(hostString) {
                    endpoint = Endpoint(host: .ipv6(ipv6), port: port)
                    peer.endpoint = endpoint
                } else {
                    endpoint = Endpoint(host: .name(hostString, nil), port: port)
                    peer.endpoint = endpoint
                }
            }

            let ipv6Str = KeyDerivation.deriveIPv6(npubHex: info.npub)
            if let addr = IPv6Address(ipv6Str) {
                peer.allowedIPs = [IPAddressRange(address: addr, networkPrefixLength: 128)]
            }
            peer.persistentKeepAlive = 25

            peers.append(peer)
        }

        let newConfig = TunnelConfiguration(name: currentConfig.name, interface: currentConfig.interface, peers: peers)
        self.tunnelConfig = newConfig

        adapter.update(tunnelConfiguration: newConfig) { _ in }
    }
}
