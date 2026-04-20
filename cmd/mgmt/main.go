package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nbd-wtf/go-nostr"

	"thedarknet/pkg/proto"
)

var (
	jwtSecret []byte
	db        *sql.DB
)

func init() {
	secret := os.Getenv("TDN_JWT_SECRET")
	if secret == "" {
		secret = "thedarknet-jwt-secret-dev" // MVP secret fallback
	}
	jwtSecret = []byte(secret)
}

type Account struct {
	ID       string `json:"id"`
	IPv6     string `json:"ipv6"`
	WGPubKey string `json:"wg_pubkey"`
}

type LoginResponse struct {
	Token   string  `json:"token"`
	Account Account `json:"account"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./thedarknet.db")
	if err != nil {
		log.Fatalf("Failed to open db: %v", err)
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
		log.Fatalf("Failed to create table: %v", err)
	}
}

func upsertPeer(npub string, ipv6 string, wgPubKey string) error {
	query := `
	INSERT INTO peers (npub, ipv6, wg_pubkey, last_seen)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(npub) DO UPDATE SET
		ipv6=excluded.ipv6,
		wg_pubkey=excluded.wg_pubkey,
		last_seen=excluded.last_seen;`
	_, err := db.Exec(query, npub, ipv6, wgPubKey, time.Now())
	return err
}

func getAllPeers() ([]Account, error) {
	rows, err := db.Query("SELECT npub, ipv6, wg_pubkey FROM peers")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []Account
	for rows.Next() {
		var p Account
		if err := rows.Scan(&p.ID, &p.IPv6, &p.WGPubKey); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}

	var req struct {
		Event nostr.Event `json:"event"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	event := req.Event
	if event.Kind != 27235 || event.Content != "thedarknet-login" {
		http.Error(w, "Invalid event kind or content", http.StatusBadRequest)
		return
	}

	ok, err := event.CheckSignature()
	if !ok || err != nil {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	npubHex := event.PubKey
	ipv6 := proto.DeriveIPv6(npubHex).String()

	// The WireGuard public key is expected to be provided in the login event tags
	// as ["wg_pubkey", "<key>"], as it cannot be derived by the management server
	// from the npub alone (it is derived from the agent's seed).
	var wgPubKey string
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "wg_pubkey" {
			wgPubKey = tag[1]
		}
	}

	if err := upsertPeer(npubHex, ipv6, wgPubKey); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": npubHex,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	resp := LoginResponse{
		Token: tokenString,
		Account: Account{
			ID:       npubHex,
			IPv6:     ipv6,
			WGPubKey: wgPubKey,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func peersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	peers, err := getAllPeers()
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

func main() {
	initDB()

	http.HandleFunc("/api/v1/login", loginHandler)
	http.HandleFunc("/api/v1/peers", peersHandler)

	fmt.Println("Starting mgmt server on :33073")
	log.Fatal(http.ListenAndServe(":33073", nil))
}
