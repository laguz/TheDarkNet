package proto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDerivePSK(t *testing.T) {
	npub1 := "npub1"
	npub2 := "npub2"

	// Test Determinism
	psk1 := DerivePSK(npub1, npub2)
	psk2 := DerivePSK(npub1, npub2)
	if !bytes.Equal(psk1, psk2) {
		t.Error("DerivePSK is not deterministic")
	}

	// Test Commutativity
	psk3 := DerivePSK(npub2, npub1)
	if !bytes.Equal(psk1, psk3) {
		t.Error("DerivePSK is not commutative")
	}

	// Test Distinctness
	psk4 := DerivePSK(npub1, "npub3")
	if bytes.Equal(psk1, psk4) {
		t.Error("DerivePSK returned same PSK for different inputs")
	}

	// Test Known Value
	// WireGuard PSK = sha256("thedarknet-psk-v1" + sort(npub1, npub2))
	// sort("npub1", "npub2") -> "npub1", "npub2"
	// sha256("thedarknet-psk-v1npub1npub2")
	expectedHex := "9d21a59301469a4ca4affc6f27271c0e60dc014bb824517ff4a687027c4154a5"
	if hex.EncodeToString(psk1) != expectedHex {
		t.Errorf("DerivePSK known value mismatch: got %s, want %s", hex.EncodeToString(psk1), expectedHex)
	}
}
