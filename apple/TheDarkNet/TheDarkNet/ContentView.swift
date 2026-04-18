import SwiftUI

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

            Button("Connect") {
                connect()
            }
            .buttonStyle(.borderedProminent)

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

    #if os(macOS)
    func installLaunchdAgents() {
        let plistNames = [
            "com.thedarknet.agent.plist",
            "com.thedarknet.hyperd.plist"
        ]

        let fileManager = FileManager.default
        let homeDir = fileManager.homeDirectoryForCurrentUser
        let userAgentsDir = homeDir.appendingPathComponent("Library/LaunchAgents")

        // Ensure ~/Library/LaunchAgents exists
        try? fileManager.createDirectory(at: userAgentsDir, withIntermediateDirectories: true)

        guard let bundleAgentsPath = Bundle.main.resourceURL?
            .deletingLastPathComponent() // Contents/Resources -> Contents
            .appendingPathComponent("Library/LaunchAgents") else {
            print("Failed to locate LaunchAgents in app bundle")
            return
        }

        let uid = getuid()

        for plistName in plistNames {
            let sourcePlist = bundleAgentsPath.appendingPathComponent(plistName)
            let destPlist = userAgentsDir.appendingPathComponent(plistName)

            // Copy plist to ~/Library/LaunchAgents/
            do {
                if fileManager.fileExists(atPath: destPlist.path) {
                    // Unload existing agent before replacing
                    let label = plistName.replacingOccurrences(of: ".plist", with: "")
                    let unload = Process()
                    unload.executableURL = URL(fileURLWithPath: "/bin/launchctl")
                    unload.arguments = ["bootout", "gui/\(uid)/\(label)"]
                    try? unload.run()
                    unload.waitUntilExit()

                    try fileManager.removeItem(at: destPlist)
                }
                try fileManager.copyItem(at: sourcePlist, to: destPlist)
            } catch {
                print("Failed to install \(plistName): \(error.localizedDescription)")
                continue
            }

            // Bootstrap the agent via launchctl
            let label = plistName.replacingOccurrences(of: ".plist", with: "")
            let load = Process()
            load.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            load.arguments = ["bootstrap", "gui/\(uid)", destPlist.path]
            do {
                try load.run()
                load.waitUntilExit()
                if load.terminationStatus == 0 {
                    print("Successfully loaded \(label)")
                } else {
                    print("launchctl bootstrap returned \(load.terminationStatus) for \(label)")
                }
            } catch {
                print("Failed to bootstrap \(label): \(error.localizedDescription)")
            }
        }
    }
    #endif
}
