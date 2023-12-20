package network

import (
	"crypto/ed25519"

	"github.com/Arceliar/ironwood/types"
)

const (
	publicKeySize  = ed25519.PublicKeySize
	privateKeySize = ed25519.PrivateKeySize
	signatureSize  = ed25519.SignatureSize
)

type domain types.Domain
type name [publicKeySize]byte
type publicKey [publicKeySize]byte
type privateKey [privateKeySize]byte
type signature [signatureSize]byte

type crypto struct {
	privateKey privateKey
	publicKey  publicKey
	domain     domain
}

func initDomain() domain {
	var n [publicKeySize]byte
	return domain{
		Key:  make([]byte, publicKeySize),
		Name: n,
	}
}

func newDomain(name string, key ed25519.PublicKey) domain {
	var n [publicKeySize]byte
	copy(n[:], []byte(name))
	return domain{
		Key:  key,
		Name: n,
	}
}

func (key *privateKey) sign(message []byte) signature {
	var sig signature
	tmp := ed25519.Sign(ed25519.PrivateKey(key[:]), message)
	copy(sig[:], tmp)
	return sig
}

func (publicKey publicKey) equal(comparedKey publicKey) bool {
	return publicKey == comparedKey
}

func (publicKey publicKey) verify(message []byte, sig *signature) bool {
	return ed25519.Verify(publicKey[:], message, sig[:])
}

func (domain domain) verify(message []byte, sig *signature) bool {
	return ed25519.Verify(domain.Key, message, sig[:])
}

func (domain domain) equal(comparedDomain domain) bool {
	return types.Domain(domain).Equal(types.Domain(comparedDomain))
}

func (key publicKey) less(comparedKey publicKey) bool {
	for idx := range key {
		switch {
		case key[idx] < comparedKey[idx]:
			return true
		case key[idx] > comparedKey[idx]:
			return false
		}
	}
	return false
}

func (domain domain) addr() types.Addr {
	return types.Addr(domain)
}

func (domain domain) publicKey() publicKey {
	return publicKey(domain.Key)
}

func (domain domain) name() name {
	return domain.Name
}

func (c *crypto) init(secret ed25519.PrivateKey, domain_ types.Domain) {
	copy(c.privateKey[:], secret)
	copy(c.publicKey[:], secret.Public().(ed25519.PublicKey))
	c.domain = domain(domain_)
}

/*********************
 * utility functions *
 *********************/
//func (domain1 domain) treeLess(domain2 domain) bool {
//	return domain1.publicKey().treeLess(domain2.publicKey())
//}

func (domain1 domain) treeLess(domain2 domain) bool {
	for idx := range domain1.Name {
		switch {
		case domain1.Name[idx] < domain2.Name[idx]:
			return true
		case domain1.Name[idx] > domain2.Name[idx]:
			return false
		}
	}
	return false
}

func (key1 name) treeLess(key2 name) bool {
	for idx := range key1 {
		switch {
		case key1[idx] < key2[idx]:
			return true
		case key1[idx] > key2[idx]:
			return false
		}
	}
	return false
}

func (key publicKey) toEd() ed25519.PublicKey {
	k := key
	return k[:]
}
