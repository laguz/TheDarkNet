package proto

import (
	"crypto/sha256"
	"sort"
)

// DerivePSK derives a Perfect Forward Secrecy pre-shared key for a WireGuard peer connection.
// WireGuard PSK = sha256("thedarknet-psk-v1" + sort(npub1, npub2))
func DerivePSK(npub1, npub2 string) []byte {
	npubs := []string{npub1, npub2}
	sort.Strings(npubs)

	h := sha256.New()
	h.Write([]byte("thedarknet-psk-v1"))
	h.Write([]byte(npubs[0]))
	h.Write([]byte(npubs[1]))
	return h.Sum(nil)
}
