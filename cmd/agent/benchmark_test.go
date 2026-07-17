package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

var benchmarkData []byte

func init() {
	peersJSON := `[`
	for i := 0; i < 1000; i++ {
		if i > 0 {
			peersJSON += `,`
		}
		peersJSON += `{"id":"npub1testing` + string(rune('a'+(i%26))) + `","wg_pubkey":"deadbeef","ipv6":"fd00::` + string(rune('0'+(i%10))) + `"}`
	}
	peersJSON += `]`
	benchmarkData = []byte(peersJSON)
}

func BenchmarkDecodePeersMap(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var peers []map[string]interface{}
		err := json.NewDecoder(bytes.NewReader(benchmarkData)).Decode(&peers)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodePeersStruct(b *testing.B) {
	type Peer struct {
		ID       string `json:"id"`
		WGPubKey string `json:"wg_pubkey"`
		IPv6     string `json:"ipv6"`
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var peers []Peer
		err := json.NewDecoder(bytes.NewReader(benchmarkData)).Decode(&peers)
		if err != nil {
			b.Fatal(err)
		}
	}
}
