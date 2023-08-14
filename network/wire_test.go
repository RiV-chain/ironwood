package network

import (
	"crypto/ed25519"
	"testing"
)

func TestNewTreeInfoKeyWire(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	info := newTreeInfo()
	copy(info.root.Key[:], pub)
	bs, err := info.encode(nil)
	if err != nil {
		panic(err)
	}
	newInfo := new(treeInfo)
	err = newInfo.decode(bs)
	if err != nil {
		panic(err)
	}
	if !info.root.Key.Equal(newInfo.root.Key) {
		panic("encoded root.Key does not match decoded root.Key")
	}
}

func TestNewTreeHopWire(t *testing.T) {
	info := newTreeInfo()
	hop := newTreeHop()
	hop.next = newDomain("example", make([]byte, 32))
	info.hops = []treeHop{hop}
	bs, err := info.encode(nil)
	if err != nil {
		panic(err)
	}
	newInfo := new(treeInfo)
	err = newInfo.decode(bs)
	if err != nil {
		panic(err)
	}
	if !info.hops[0].next.equal(newInfo.hops[0].next) {
		panic("encoded hop does not match decoded hop")
	}
}
