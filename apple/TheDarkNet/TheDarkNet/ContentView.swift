import SwiftUI
#if os(macOS)
import ServiceManagement
#endif

struct ContentView: View {
    @State private var nsecInput: String = ""
    @State private var statusMessage: String = "Disconnected"

    var body: some View {
        VStack(spacing: 20) {
            Text("TheDarkNet")
                .font(.largeTitle)
                .bold()

            SecureField("Paste nsec1...", text: $nsecInput)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .frame(width: 300)

            HStack {
                Button("Connect") {
                    connect()
                }
                .buttonStyle(.borderedProminent)

                Button("Disconnect") {
                    disconnect()
                }
                .buttonStyle(.bordered)
            }

            Text(statusMessage)
                .foregroundColor(.gray)
        }
        .padding(40)
    }

    func connect() {
        guard !nsecInput.isEmpty else {
            statusMessage = "Please enter an nsec"
            return
        }

        statusMessage = "Connecting..."

        // Save to keychain service "com.thedarknet" account "nsec"
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "nsec",
            kSecAttrService as String: "com.thedarknet",
            kSecValueData as String: nsecInput.data(using: .utf8)!
        ]
        SecItemDelete(addQuery as CFDictionary)
        SecItemAdd(addQuery as CFDictionary, nil)

        // Write to ~/Library/Application Support/TheDarkNet/nsec with 0600 permissions
        let fileManager = FileManager.default
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let tdnDir = appSupport.appendingPathComponent("TheDarkNet")

        do {
            try fileManager.createDirectory(at: tdnDir, withIntermediateDirectories: true)
            let nsecURL = tdnDir.appendingPathComponent("nsec")

            try nsecInput.write(to: nsecURL, atomically: true, encoding: .utf8)

            // Set 0600 permissions
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: nsecURL.path)

            statusMessage = "Connected as fd00:..." // normally would derive the IP

            // Install and load launchd agents
            #if os(macOS)
            installLaunchdAgents()
            #endif
        } catch {
            statusMessage = "Failed to save nsec: \(error.localizedDescription)"
        }
    }

    func disconnect() {
        statusMessage = "Disconnecting..."

        #if os(macOS)
        uninstallLaunchdAgents()
        #endif

        statusMessage = "Disconnected"
    }

    #if os(macOS)
    func installLaunchdAgents() {
        let plistNames = [
            "com.thedarknet.agent.plist",
            "com.thedarknet.hyperd.plist"
        ]

        for plistName in plistNames {
            let agent = SMAppService.agent(plistName: plistName)
            do {
                try agent.register()
                print("Successfully loaded \(plistName)")
            } catch {
                print("Failed to register \(plistName): \(error.localizedDescription)")
            }
        }
    }

    func uninstallLaunchdAgents() {
        let plistNames = [
            "com.thedarknet.agent.plist",
            "com.thedarknet.hyperd.plist"
        ]

        for plistName in plistNames {
            let agent = SMAppService.agent(plistName: plistName)
            do {
                try agent.unregister()
                print("Successfully unloaded \(plistName)")
            } catch {
                print("Failed to unregister \(plistName): \(error.localizedDescription)")
            }
        }
    }
    #endif
}
