package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"thedarknet/pkg/proto"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open db: %v", err)
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS peers (
		npub TEXT PRIMARY KEY,
		ipv6 TEXT,
		wg_pubkey TEXT,
		last_seen DATETIME
	);`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
}

func TestLoginHandler(t *testing.T) {
	os.Setenv("TDN_JWT_SECRET", "testsecret")
	jwtSecret = []byte("testsecret")
	setupTestDB(t)
	defer db.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	validWgPubKey := "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2" // 64 hex chars

	tests := []struct {
		name           string
		method         string
		modifyEvent    func(e *nostr.Event)
		badSignature   bool
		invalidBody    bool
		expectedStatus int
	}{
		{
			name:           "Method Not Allowed",
			method:         http.MethodGet,
			modifyEvent:    func(e *nostr.Event) {},
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "Valid Login",
			method: http.MethodPost,
			modifyEvent: func(e *nostr.Event) {
				e.Tags = nostr.Tags{{"wg_pubkey", validWgPubKey}}
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Invalid Event Kind",
			method: http.MethodPost,
			modifyEvent: func(e *nostr.Event) {
				e.Kind = 1
				e.Tags = nostr.Tags{{"wg_pubkey", validWgPubKey}}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid Event Content",
			method: http.MethodPost,
			modifyEvent: func(e *nostr.Event) {
				e.Content = "bad content"
				e.Tags = nostr.Tags{{"wg_pubkey", validWgPubKey}}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Missing WG PubKey",
			method: http.MethodPost,
			modifyEvent: func(e *nostr.Event) {
				// No tags
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid WG PubKey Format",
			method: http.MethodPost,
			modifyEvent: func(e *nostr.Event) {
				e.Tags = nostr.Tags{{"wg_pubkey", "short"}}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid Signature",
			method: http.MethodPost,
			modifyEvent: func(e *nostr.Event) {
				e.Tags = nostr.Tags{{"wg_pubkey", validWgPubKey}}
			},
			badSignature:   true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Body JSON",
			method:         http.MethodPost,
			invalidBody:    true,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reqBody []byte

			if tc.invalidBody {
				reqBody = []byte("invalid json")
			} else {
				ev := &nostr.Event{
					PubKey:    pk,
					CreatedAt: nostr.Timestamp(time.Now().Unix()),
					Kind:      proto.LoginEventKind,
					Content:   proto.LoginEventContent,
				}
				if tc.modifyEvent != nil {
					tc.modifyEvent(ev)
				}

				// We only sign it if it's a POST and we actually want to test the event processing
				if tc.method == http.MethodPost {
					ev.Sign(sk)
					if tc.badSignature {
						ev.Sig = "badsig" + ev.Sig[6:] // Mangle signature
					}
				}

				reqBody, _ = json.Marshal(map[string]interface{}{
					"event": ev,
				})
			}

			req := httptest.NewRequest(tc.method, "/api/v1/login", bytes.NewBuffer(reqBody))
			w := httptest.NewRecorder()

			loginHandler(w, req)

			if w.Result().StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, w.Result().StatusCode)
			}

			if tc.expectedStatus == http.StatusOK {
				var resp LoginResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Errorf("failed to decode response: %v", err)
				}
				if resp.Token == "" {
					t.Errorf("expected token in response")
				}
				if resp.Account.ID != pk {
					t.Errorf("expected account ID %s, got %s", pk, resp.Account.ID)
				}
				if resp.Account.WGPubKey != validWgPubKey {
					t.Errorf("expected WG PubKey %s, got %s", validWgPubKey, resp.Account.WGPubKey)
				}
			}
		})
	}
}
