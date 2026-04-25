package main

import (
	"testing"
)

func TestIsValidWGPubKey(t *testing.T) {
	tests := []struct {
		name     string
		pubkey   string
		expected bool
	}{
		{"Valid key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", true},
		{"Short key", "00010203", false},
		{"Long key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1234", false},
		{"Invalid hex", "zzzz02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidWGPubKey(tt.pubkey); got != tt.expected {
				t.Errorf("isValidWGPubKey(%v) = %v, want %v", tt.pubkey, got, tt.expected)
			}
		})
	}
}
