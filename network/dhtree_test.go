package network

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"testing"

	"github.com/Arceliar/ironwood/types"
)

func TestMarshalTreeInfo(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	var sk privateKey
	copy(sk[:], priv)
	info := newTreeInfo()
	info.root.Key = pub
	info.seq = 16777215
	for idx := 0; idx < 10; idx++ {
		newPub, newPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		info = *info.add(sk, &peer{domain: newDomain("example", newPub)})
		if !info.checkSigs() {
			t.Log(len(info.hops))
			t.Log(info.hops[len(info.hops)-1].sig)
			panic("checkSigs failed")
		} else if !info.checkLoops() {
			panic("checkLoops failed")
		}
		copy(sk[:], newPriv)
	}
	bs, err := info.encode(nil)
	if err != nil {
		panic(err)
	}
	newInfo := newTreeInfo()
	err = newInfo.decode(bs)
	if err != nil {
		panic(err)
	}
	if !info.root.equal(newInfo.root) {
		panic("unequal roots")
	}
	if len(newInfo.hops) != len(info.hops) {
		panic("unequal number of hops")
	}
	for idx := range newInfo.hops {
		newHop := newInfo.hops[idx]
		hop := info.hops[idx]
		if !newHop.next.equal(hop.next) {
			panic("unequal next")
		}
		if !bytes.Equal(newHop.sig[:], hop.sig[:]) {
			panic("unequal sig")
		}
	}
	if !newInfo.checkSigs() {
		panic("new checkSigs failed")
	} else if !newInfo.checkLoops() {
		panic("new checkLoops failed")
	}
}

func TestMarshalDHTBootstrap(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	var sk privateKey
	copy(sk[:], priv)
	info := newTreeInfo()
	copy(info.root.Key[:], pub)
	copy(info.root.Name[:], []byte("doom"))
	for idx := 0; idx < 10; idx++ {
		newPub, newPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		info = *info.add(sk, &peer{domain: newDomain("example"+strconv.Itoa(idx), newPub), port: 1})
		if !info.checkSigs() {
			panic("checkSigs failed")
		} else if !info.checkLoops() {
			panic("checkLoops failed")
		}
		copy(sk[:], newPriv)
	}
	c := new(core)
	d := types.Domain(newDomain("example", pub))
	c.init(priv, d)
	c.dhtree.self = &info
	bootstrap := newBootstrap()
	bootstrap.label = c.dhtree._getLabel()
	if !bootstrap.check() {
		panic("failed to check bootstrap")
	}
	bs, err := bootstrap.encode(nil)
	if err != nil {
		panic(err)
	}
	newBootstrap := newBootstrap()
	err = newBootstrap.decode(bs)
	if err != nil {
		panic(err)
	}
	if !newBootstrap.check() {
		panic("failed to check new bootstrap")
	}
}

func TestMarshalDHTSetup(t *testing.T) {
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	sourcePub, sourcePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	dest := types.Domain(newDomain("d1", destPub))
	src := types.Domain(newDomain("d2", sourcePub))
	dpc, _ := NewPacketConn(destPriv, dest)
	spc, _ := NewPacketConn(sourcePriv, src)
	token := dpc.core.dhtree._getToken(domain(src))
	setup := spc.core.dhtree._newSetup(token)
	if !setup.check() {
		panic("initial check failed")
	}
	bs, err := setup.encode(nil)
	if err != nil {
		panic(err)
	}
	newSetup := new(dhtSetup)
	if err = newSetup.decode(bs); err != nil {
		panic(err)
	}
	if !newSetup.check() {
		panic("final check failed")
	}
}
