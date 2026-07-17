package proto

import (
	"crypto/sha256"
)

// DerivePSK derives a Perfect Forward Secrecy pre-shared key for a WireGuard peer connection.
// WireGuard PSK = sha256("thedarknet-psk-v1" + sort(npub1, npub2))
func DerivePSK(npub1, npub2 string) []byte {
	if npub1 > npub2 {
		npub1, npub2 = npub2, npub1
	}

	h := sha256.New()
	h.Write([]byte("thedarknet-psk-v1"))
	h.Write([]byte(npub1))
	h.Write([]byte(npub2))
	return h.Sum(nil)
}
