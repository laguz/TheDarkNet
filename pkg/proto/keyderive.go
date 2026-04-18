package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// DecodeNsec returns the 32-byte Ed25519 seed from an nsec string
// which can be bech32 nsec1... or 64-char hex.
func DecodeNsec(nsec string) ([]byte, error) {
	if strings.HasPrefix(nsec, "nsec1") {
		prefix, data, err := nip19.Decode(nsec)
		if err != nil {
			return nil, err
		}
		if prefix != "nsec" {
			return nil, fmt.Errorf("invalid prefix: %s", prefix)
		}
		hexStr, ok := data.(string)
		if !ok {
			return nil, fmt.Errorf("invalid nsec data type")
		}
		return hex.DecodeString(hexStr)
	}

	// Assume hex
	if len(nsec) != 64 {
		return nil, fmt.Errorf("invalid hex nsec length, expected 64")
	}
	return hex.DecodeString(nsec)
}

// DeriveNpubHex returns the hex npub from the Ed25519 seed.
func DeriveNpubHex(seed []byte) string {
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(publicKey)
}

// DeriveWGPrivate returns the WireGuard private key from the seed.
func DeriveWGPrivate(seed []byte) []byte {
	h := sha256.New()
	h.Write([]byte("thedarknet-wg-v1"))
	h.Write(seed)
	return h.Sum(nil)[:32]
}

// DeriveWGPublic returns the WireGuard public key from the WG private key.
func DeriveWGPublic(wgPrivate []byte) []byte {
	var pub, priv [32]byte
	copy(priv[:], wgPrivate)
	curve25519.ScalarBaseMult(&pub, &priv)
	return pub[:]
}

// DeriveIPv6 returns the fd00::/8 IPv6 address from npub hex string.
func DeriveIPv6(npubHex string) netip.Addr {
	h := sha256.New()
	h.Write([]byte("thedarknet-ipv6-v1"))
	h.Write([]byte(npubHex))
	sum := h.Sum(nil)

	// fd00::/8 | sha256[:14] | 0x01
	var ip [16]byte
	ip[0] = 0xfd
	ip[1] = 0x00
	copy(ip[2:15], sum[:13])
	ip[15] = 0x01

	addr := netip.AddrFrom16(ip)
	return addr
}
