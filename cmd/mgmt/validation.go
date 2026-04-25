package main

import "encoding/hex"

func isValidWGPubKey(pubkey string) bool {
	if len(pubkey) != 64 {
		return false
	}
	_, err := hex.DecodeString(pubkey)
	return err == nil
}
