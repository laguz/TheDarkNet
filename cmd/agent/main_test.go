package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestLoginToMgmt(t *testing.T) {
	validSeed := make([]byte, 32)
	validSeed[0] = 1 // non-zero seed
	invalidSeed := make([]byte, 32) // zero seed

	npubHex := "testnpubhex"
	wgPubKeyHex := "testwgpubkeyhex"

	t.Run("Happy Path", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/login" {
				t.Errorf("expected path /api/v1/login, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token": "test-token"}`))
		}))
		defer ts.Close()

		// Save and restore global mgmtURL
		oldURL := mgmtURL
		mgmtURL = ts.URL
		defer func() { mgmtURL = oldURL }()

		err := loginToMgmt(validSeed, npubHex, wgPubKeyHex)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if jwtToken != "test-token" {
			t.Errorf("expected token 'test-token', got '%s'", jwtToken)
		}
	})

	t.Run("Sign Event Error", func(t *testing.T) {
		err := loginToMgmt(invalidSeed, npubHex, wgPubKeyHex)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "sign event") {
			t.Errorf("expected 'sign event' error, got %v", err)
		}
	})

	t.Run("HTTP Connection Error", func(t *testing.T) {
		oldURL := mgmtURL
		mgmtURL = "http://127.0.0.1:0" // invalid port
		defer func() { mgmtURL = oldURL }()

		err := loginToMgmt(validSeed, npubHex, wgPubKeyHex)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "post login") {
			t.Errorf("expected 'post login' error, got %v", err)
		}
	})

	t.Run("HTTP Status Error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		oldURL := mgmtURL
		mgmtURL = ts.URL
		defer func() { mgmtURL = oldURL }()

		err := loginToMgmt(validSeed, npubHex, wgPubKeyHex)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := "login failed with status 500"
		if err.Error() != expectedErr {
			t.Errorf("expected '%s', got '%v'", expectedErr, err)
		}
	})

	t.Run("JSON Decode Error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{invalid-json}`))
		}))
		defer ts.Close()

		oldURL := mgmtURL
		mgmtURL = ts.URL
		defer func() { mgmtURL = oldURL }()

		err := loginToMgmt(validSeed, npubHex, wgPubKeyHex)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "decode token") {
			t.Errorf("expected 'decode token' error, got %v", err)
		}
	})
}
