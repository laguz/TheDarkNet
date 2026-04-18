import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {

        // This is a stub for NEPacketTunnelProvider that would in reality use WireGuardKit
        // and connect to the locally spawned hyperd node.js process via JavaScriptCore
        // or a bundled node binary.

        let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let ipv6Settings = NEIPv6Settings(addresses: ["fd00::1"], networkPrefixLengths: [128])
        ipv6Settings.includedRoutes = [NEIPv6Route(destinationAddress: "fd00::", networkPrefixLength: 8)]

        tunnelNetworkSettings.ipv6Settings = ipv6Settings
        tunnelNetworkSettings.mtu = 1280

        setTunnelNetworkSettings(tunnelNetworkSettings) { error in
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
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
}
