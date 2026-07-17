import re

with open("apple/TheDarkNet/TheDarkNet/ContentView.swift", "r") as f:
    content = f.read()

# Replace runLaunchctl calls with SMAppService.agent(plistName: ...).register()
# and import ServiceManagement.

if "import ServiceManagement" not in content:
    content = content.replace("internal import Combine", "internal import Combine\nimport ServiceManagement")

# We want to use SMAppService.agent(plistName: "\(name).plist").register()
# instead of runLaunchctl in install()
# and SMAppService.agent(plistName: "\(name).plist").unregister() in uninstall()

old_install = """            _ = try? runLaunchctl(["bootout", "gui/\(uid)", dest.path])
            try runLaunchctl(["bootstrap", "gui/\(uid)", dest.path])
            installed.append(name)"""

new_install = """            if #available(macOS 13.0, *) {
                let agent = SMAppService.agent(plistName: "\(name).plist")
                try? agent.unregister() // ignore error if not registered
                try agent.register()
            } else {
                _ = try? runLaunchctl(["bootout", "gui/\(uid)", dest.path])
                try runLaunchctl(["bootstrap", "gui/\(uid)", dest.path])
            }
            installed.append(name)"""

content = content.replace(old_install, new_install)

old_uninstall = """            _ = try? runLaunchctl(["bootout", "gui/\(uid)", plist.path])
            try? FileManager.default.removeItem(at: plist)"""

new_uninstall = """            if #available(macOS 13.0, *) {
                let agent = SMAppService.agent(plistName: "\(name).plist")
                try? agent.unregister()
            } else {
                _ = try? runLaunchctl(["bootout", "gui/\(uid)", plist.path])
            }
            try? FileManager.default.removeItem(at: plist)"""

content = content.replace(old_uninstall, new_uninstall)

with open("apple/TheDarkNet/TheDarkNet/ContentView.swift", "w") as f:
    f.write(content)
