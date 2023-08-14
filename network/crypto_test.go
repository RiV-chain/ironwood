package network

import (
	"crypto/ed25519"
	"testing"

	"github.com/Arceliar/ironwood/types"
)

func TestSign(t *testing.T) {
	var c crypto
	_, priv, _ := ed25519.GenerateKey(nil)
	d := types.Domain{}
	c.init(priv, d)
	msg := []byte("this is a test")
	_ = c.privateKey.sign(msg)
}

func TestVerify(t *testing.T) {
	var c crypto
	pub, priv, _ := ed25519.GenerateKey(nil)
	d := types.Domain(newDomain("verify", pub))
	c.init(priv, d)
	msg := []byte("this is a test")
	sig := c.privateKey.sign(msg)
	if !c.domain.verify(msg, &sig) {
		panic("verification failed")
	}
}

func BenchmarkSign(b *testing.B) {
	var c crypto
	_, priv, _ := ed25519.GenerateKey(nil)
	d := types.Domain{}
	c.init(priv, d)
	msg := []byte("this is a test")
	for idx := 0; idx < b.N; idx++ {
		_ = c.privateKey.sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	var c crypto
	pub, priv, _ := ed25519.GenerateKey(nil)
	d := types.Domain(newDomain("verify", pub))
	c.init(priv, d)
	msg := []byte("this is a test")
	sig := c.privateKey.sign(msg)
	for idx := 0; idx < b.N; idx++ {
		if !c.domain.verify(msg, &sig) {
			panic("verification failed")
		}
	}
}
