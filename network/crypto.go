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
	return domain{
		Key:  make([]byte, publicKeySize),
		Name: make([]byte, publicKeySize),
	}
}

func newDomain(name string, key ed25519.PublicKey) domain {
	return domain{
		Key:  key,
		Name: append([]byte(name), make([]byte, publicKeySize-len([]byte(name)))...),
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

func (domain domain) verify(message []byte, sig *signature) bool {
	return ed25519.Verify(domain.Key, message, sig[:])
}

func (domain domain) equal(comparedDomain domain) bool {
	return types.Domain(domain).Equal(types.Domain(comparedDomain))
}

func (domain domain) addr() types.Addr {
	return types.Addr(domain)
}

func (domain domain) publicKey() publicKey {
	return publicKey(domain.Key)
}

func (domain domain) name() name {
	return name(domain.Name)
}

func (c *crypto) init(secret ed25519.PrivateKey, domain_ types.Domain) {
	copy(c.privateKey[:], secret)
	c.domain = domain(domain_)
}

/*********************
 * utility functions *
 *********************/
//func (domain1 domain) treeLess(domain2 domain) bool {
//	return domain1.publicKey().treeLess(domain2.publicKey())
//}

func (first domain) dhtOrdered(second, third domain) bool {
	return first.treeLess(second) && second.treeLess(third)
}

/*
func (key1 publicKey) treeLess(key2 publicKey) bool {
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
*/

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
