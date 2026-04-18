package proto

import (
	"encoding/hex"
	"testing"
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
