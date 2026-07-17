package main

import (
	"encoding/hex"
	"net"
	"testing"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"thedarknet/pkg/proto"
)

func BenchmarkPeerProcessingOriginal(b *testing.B) {
	// Setup mock data
	npub := "npub1mock"
	peers := []map[string]interface{}{}

	for i := 0; i < 100; i++ {
		peerNpub := "npub1peer" + string(rune(i))
		peerIPv6 := "fd00::1"
		peerWgPubHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		peers = append(peers, map[string]interface{}{
			"id": peerNpub,
			"ipv6": peerIPv6,
			"wg_pubkey": peerWgPubHex,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wgPeers []wgtypes.PeerConfig

		for _, p := range peers {
			peerNpub := p["id"].(string)
			if peerNpub == npub {
				continue
			}

			peerWgPubHex := p["wg_pubkey"].(string)
			peerWgPubBytes, _ := hex.DecodeString(peerWgPubHex)
			var peerWgPub wgtypes.Key
			copy(peerWgPub[:], peerWgPubBytes)

			peerIPv6 := p["ipv6"].(string)
			_, peerIPNet, _ := net.ParseCIDR(peerIPv6 + "/128")

			var psk wgtypes.Key
			pskBytes := proto.DerivePSK(npub, peerNpub)
			copy(psk[:], pskBytes)

			wgPeers = append(wgPeers, wgtypes.PeerConfig{
				PublicKey:         peerWgPub,
				PresharedKey:      &psk,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{*peerIPNet},
			})
		}
		_ = wgPeers
	}
}

func BenchmarkPeerProcessingOptimized(b *testing.B) {
	// Setup mock data
	npub := "npub1mock"
	peers := []map[string]interface{}{}

	for i := 0; i < 100; i++ {
		peerNpub := "npub1peer" + string(rune(i))
		peerIPv6 := "fd00::1"
		peerWgPubHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		peers = append(peers, map[string]interface{}{
			"id": peerNpub,
			"ipv6": peerIPv6,
			"wg_pubkey": peerWgPubHex,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wgPeers []wgtypes.PeerConfig

		for _, p := range peers {
			peerNpub := p["id"].(string)
			if peerNpub == npub {
				continue
			}

			cacheKey := npub + ":" + peerNpub

			cacheMu.RLock()
			entry, ok := peerCache[cacheKey]
			cacheMu.RUnlock()

			if !ok {
				peerWgPubHex := p["wg_pubkey"].(string)
				peerWgPubBytes, _ := hex.DecodeString(peerWgPubHex)
				var peerWgPub wgtypes.Key
				copy(peerWgPub[:], peerWgPubBytes)

				peerIPv6 := p["ipv6"].(string)
				_, peerIPNet, _ := net.ParseCIDR(peerIPv6 + "/128")

				var psk wgtypes.Key
				pskBytes := proto.DerivePSK(npub, peerNpub)
				copy(psk[:], pskBytes)

				entry = peerCacheEntry{
					wgPub: peerWgPub,
					ipNet: *peerIPNet,
					psk:   psk,
				}

				cacheMu.Lock()
				peerCache[cacheKey] = entry
				cacheMu.Unlock()
			}

			wgPeers = append(wgPeers, wgtypes.PeerConfig{
				PublicKey:         entry.wgPub,
				PresharedKey:      &entry.psk,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{entry.ipNet},
			})
		}
		_ = wgPeers
	}
}
