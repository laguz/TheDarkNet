package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sync"

	"github.com/nbd-wtf/go-nostr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"thedarknet/pkg/proto"
)

var (
	mgmtURL  string
	jwtToken string
	appDir   string
	wgIface  string
)

type peerCacheEntry struct {
	wgPub wgtypes.Key
	ipNet net.IPNet
	psk   wgtypes.Key
}

var (
	peerCache = make(map[string]peerCacheEntry)
	cacheMu   sync.RWMutex
)

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home dir: %v", err)
	}
	appDir = filepath.Join(home, "Library", "Application Support", "TheDarkNet")

	mgmtURL = os.Getenv("TDN_MGMT_URL")
	if mgmtURL == "" {
		mgmtURL = "http://127.0.0.1:33073"
	}

	wgIface = os.Getenv("TDN_WG_IFACE")
	if wgIface == "" {
		wgIface = "utun8"
	}
}

func readNsec() string {
	nsec := os.Getenv("TDN_NSEC")
	if nsec != "" {
		return nsec
	}

	nsecPath := filepath.Join(appDir, "nsec")
	data, err := os.ReadFile(nsecPath)
	if err != nil {
		log.Fatalf("Failed to read nsec: %v", err)
	}

	// ensure 0600 on the file
	info, err := os.Stat(nsecPath)
	if err == nil && info.Mode().Perm() != 0600 {
		os.Chmod(nsecPath, 0600)
	}

	return strings.TrimSpace(string(data))
}

func loginToMgmt(seed []byte, npubHex, wgPubKeyHex string) error {
	ev := nostr.Event{
		PubKey:    npubHex,
		CreatedAt: nostr.Now(),
		Kind:      proto.LoginEventKind,
		Tags:      nostr.Tags{{"wg_pubkey", wgPubKeyHex}},
		Content:   proto.LoginEventContent,
	}

	privHex := hex.EncodeToString(seed)
	if err := ev.Sign(privHex); err != nil {
		return fmt.Errorf("sign event: %w", err)
	}

	body, _ := json.Marshal(map[string]interface{}{"event": ev})

	resp, err := http.Post(mgmtURL+"/api/v1/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("post login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	jwtToken = result.Token
	return nil
}

func getPeersFromMgmt() ([]map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", mgmtURL+"/api/v1/peers", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get peers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("get peers failed with status %d", resp.StatusCode)
	}

	var peers []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, fmt.Errorf("decode peers: %w", err)
	}
	return peers, nil
}

func getEndpointsFromHyperd() (map[string]string, error) {
	sockPath := filepath.Join(appDir, "hyperd.sock")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("dial hyperd: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("get-peers\n")); err != nil {
		return nil, fmt.Errorf("write get-peers: %w", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(conn)

	var data []struct {
		Npub     string `json:"npub"`
		Endpoint string `json:"endpoint"`
	}

	if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
		return nil, fmt.Errorf("unmarshal hyperd response: %w", err)
	}

	endpoints := make(map[string]string)
	for _, p := range data {
		endpoints[p.Npub] = p.Endpoint
	}
	return endpoints, nil
}

var ifaceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

func isValidIface(ifName string) bool {
	return ifaceNameRegex.MatchString(ifName)
}

func setupWireGuard(wgPriv []byte, ipv6 string) error {
	ifName := wgIface
	if !isValidIface(ifName) {
		return fmt.Errorf("invalid interface name: %s", ifName)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl new: %w", err)
	}
	defer client.Close()

	var wgKey wgtypes.Key
	copy(wgKey[:], wgPriv)

	port := 51820
	cfg := wgtypes.Config{
		PrivateKey: &wgKey,
		ListenPort: &port,
	}

	err = client.ConfigureDevice(ifName, cfg)
	if err != nil {
		log.Printf("Failed to configure %s, trying to create it via wireguard-go... (%v)", ifName, err)
		if out, err := exec.Command("wireguard-go", ifName).CombinedOutput(); err != nil {
			log.Printf("Warning: wireguard-go failed: %v, output: %s", err, string(out))
		}
		time.Sleep(1 * time.Second)
		err = client.ConfigureDevice(ifName, cfg)
		if err != nil {
			return fmt.Errorf("configure device %s: %w", ifName, err)
		}
	}

	if out, err := exec.Command("ifconfig", ifName, "inet6", ipv6+"/128", "alias").CombinedOutput(); err != nil {
		log.Printf("Warning: failed to add ipv6 alias: %v, output: %s", err, string(out))
	}
	if out, err := exec.Command("ifconfig", ifName, "mtu", "1280").CombinedOutput(); err != nil {
		log.Printf("Warning: failed to set mtu: %v, output: %s", err, string(out))
	}
	if out, err := exec.Command("ifconfig", ifName, "up").CombinedOutput(); err != nil {
		log.Printf("Warning: failed to bring interface up: %v, output: %s", err, string(out))
	}

	return nil
}

func syncPeers(client *wgctrl.Client, ifName string, wgPriv []byte, npub string) error {
	peers, err := getPeersFromMgmt()
	if err != nil {
		return err
	}

	endpoints, err := getEndpointsFromHyperd()
	if err != nil {
		log.Printf("Warning: failed to get endpoints from hyperd: %v", err)
	}

	var wgPeers []wgtypes.PeerConfig

	for _, p := range peers {
		peerNpub := p["id"].(string)
		if peerNpub == npub {
			continue
		}

		cacheKey := npub + ":" + peerNpub

		cacheMu.RLock()
		entry, ok := peerCache[cacheKey]
		cacheMu.RUnlock()

		if !ok {
			peerWgPubHex := p["wg_pubkey"].(string)
			peerWgPubBytes, _ := hex.DecodeString(peerWgPubHex)
			var peerWgPub wgtypes.Key
			copy(peerWgPub[:], peerWgPubBytes)

			peerIPv6 := p["ipv6"].(string)
			_, peerIPNet, _ := net.ParseCIDR(peerIPv6 + "/128")

			var psk wgtypes.Key
			pskBytes := proto.DerivePSK(npub, peerNpub)
			copy(psk[:], pskBytes)

			entry = peerCacheEntry{
				wgPub: peerWgPub,
				ipNet: *peerIPNet,
				psk:   psk,
			}

			cacheMu.Lock()
			peerCache[cacheKey] = entry
			cacheMu.Unlock()
		}

		var endpoint *net.UDPAddr
		if epStr, ok := endpoints[peerNpub]; ok && epStr != "" {
			endpoint, _ = net.ResolveUDPAddr("udp", epStr)
		}

		wgPeers = append(wgPeers, wgtypes.PeerConfig{
			PublicKey:         entry.wgPub,
			PresharedKey:      &entry.psk,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{entry.ipNet},
			Endpoint:          endpoint,
		})
	}

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers:        wgPeers,
	}

	return client.ConfigureDevice(ifName, cfg)
}

func main() {
	nsec := readNsec()
	seed, err := proto.DecodeNsec(nsec)
	if err != nil {
		log.Fatalf("Invalid nsec: %v", err)
	}

	npubHex := proto.DeriveNpubHex(seed)
	ipv6 := proto.DeriveIPv6(npubHex).String()
	wgPriv := proto.DeriveWGPrivate(seed)
	wgPub := proto.DeriveWGPublic(wgPriv)

	log.Printf("Agent starting. Npub: %s, IPv6: %s", npubHex, ipv6)

	for {
		err := loginToMgmt(seed, npubHex, hex.EncodeToString(wgPub))
		if err != nil {
			log.Printf("Login failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	log.Println("Logged into mgmt")

	ifName := wgIface
	if err := setupWireGuard(ifName, wgPriv, ipv6); err != nil {
		log.Printf("WireGuard setup error: %v", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		log.Fatalf("Failed to open wgctrl: %v", err)
	}
	defer client.Close()

	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		if err := syncPeers(client, ifName, wgPriv, npubHex); err != nil {
			log.Printf("Sync error: %v", err)
		}
	}
}
