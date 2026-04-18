# TheDarkNet

A native macOS + iOS WireGuard IPv6 mesh network using Nostr keys and Hyperswarm.

## Overview
1. Identity: Nostr nsec/npub
2. Peer discovery: Hypercore/Hyperswarm
3. Network: IPv6-only ULA fd00::/8. IPv6 is deterministically derived from npub.
4. Platforms: macOS menu bar app, iOS app

## Quick Start
```sh
make deps
make build
make install

# Setup Nsec (development only)
mkdir -p ~/Library/Application\ Support/TheDarkNet
echo "nsec1..." > ~/Library/Application\ Support/TheDarkNet/nsec

# Run services
make run-mgmt &
make run-hyperd &
sudo make run-agent
```
