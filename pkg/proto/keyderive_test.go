package proto

import (
	"encoding/hex"
	"testing"

	"github.com/nbd-wtf/go-nostr/nip19"
)

func TestKeyDerivations(t *testing.T) {
	// A fixed nsec for testing. We'll use 32 bytes of 0x01.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 1
	}
	seedHex := hex.EncodeToString(seed)

	npubHex := DeriveNpubHex(seed)
	if npubHex == "" {
		t.Fatal("empty npub")
	}

	wgPriv := DeriveWGPrivate(seed)
	if len(wgPriv) != 32 {
		t.Fatal("wg_private wrong length")
	}

	wgPub := DeriveWGPublic(wgPriv)
	if len(wgPub) != 32 {
		t.Fatal("wg_public wrong length")
	}

	ip := DeriveIPv6(npubHex)
	if !ip.IsValid() || !ip.Is6() {
		t.Fatal("invalid ipv6")
	}
	if ip.As16()[0] != 0xfd || ip.As16()[1] != 0x00 {
		t.Fatal("ipv6 not in fd00::/8")
	}

	// Just a quick check that it returns same result consistently
	npubHex2 := DeriveNpubHex(seed)
	if npubHex != npubHex2 {
		t.Fatal("non-deterministic npub")
	}

	decodedSeed, err := DecodeNsec(seedHex)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if hex.EncodeToString(decodedSeed) != seedHex {
		t.Fatal("decode mismatch")
	}
}

func TestDecodeNsec(t *testing.T) {
	validSeed := make([]byte, 32)
	for i := range validSeed {
		validSeed[i] = 0xab
	}
	validHex := hex.EncodeToString(validSeed)
	validNsec, _ := nip19.EncodePrivateKey(validHex)

	tests := []struct {
		name    string
		nsec    string
		wantHex string
		wantErr bool
	}{
		{"valid hex", validHex, false},
		{"valid bech32 nsec1", validNsec, false},
		{"invalid hex length (too short)", validHex[:63], true},
		{"invalid hex length (too long)", validHex + "0", true},
		{"invalid hex characters", "z" + validHex[1:], true},
		{"empty string", "", true},
		{"nsec1 prefix but too short", "nsec1", true},
		{"nsec1 prefix with invalid bech32", "nsec1invalidchars!!", true},
		{"invalid bech32 nsec1 (too short)", "nsec1qqqq", true},
		{"invalid bech32 nsec1 (invalid checksum)", "nsec1800d642clcd630czradxe7ww9665v066v2ueu7863p6f7sc94x7shnll07", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeNsec(tt.nsec)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeNsec(%q) error = %v, wantErr %v", tt.nsec, err, tt.wantErr)
				return
			}
			if !tt.wantErr && hex.EncodeToString(got) != validHex {
				t.Errorf("DecodeNsec(%q) = %x, want %s", tt.nsec, hex.EncodeToString(got), validHex)
			}
		})
	}
}
