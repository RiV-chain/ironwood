package network

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/Arceliar/ironwood/types"
)

func TestSign(t *testing.T) {
	var c crypto
	_, priv, _ := ed25519.GenerateKey(nil)
	d1, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	c.init(priv, types.Domain(d1))
	msg := []byte("this is a test")
	_ = c.privateKey.sign(msg)
}

func BenchmarkSign(b *testing.B) {
	var c crypto
	_, priv, _ := ed25519.GenerateKey(nil)
	d1, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	c.init(priv, types.Domain(d1))
	msg := []byte("this is a test")
	for idx := 0; idx < b.N; idx++ {
		_ = c.privateKey.sign(msg)
	}
}
