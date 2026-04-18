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
            try fileManager.setAttributes([.posixPermissions: 0o600], let: nsecURL.path)

            statusMessage = "Connected as fd00:..." // normally would derive the IP

            // Start launchd agents
            // In a real app we'd use SMAppService.agent(plistName: "com.thedarknet.agent.plist").register()
        } catch {
            statusMessage = "Failed to save nsec: \(error.localizedDescription)"
        }
    }
}
