package main

import (
	"testing"
)

func TestIsValidIface(t *testing.T) {
	tests := []struct {
		name     string
		ifName   string
		expected bool
	}{
		{"Valid wg0", "wg0", true},
		{"Valid utun8", "utun8", true},
		{"Valid all letters", "utun", true},
		{"Valid all numbers", "123", true},
		{"Invalid with dash", "utun-8", false},
		{"Invalid with spaces", "wg 0", false},
		{"Invalid with slash", "utun8/test", false},
		{"Invalid shell injection", "utun8;rm -rf /", false},
		{"Invalid empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidIface(tc.ifName)
			if result != tc.expected {
				t.Errorf("isValidIface(%q) = %v; expected %v", tc.ifName, result, tc.expected)
			}
		})
	}
}
