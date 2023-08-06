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

type publicDomain [publicKeySize]byte
type publicKey [publicKeySize]byte
type privateKey [privateKeySize]byte
type signature [signatureSize]byte

type crypto struct {
	privateKey   privateKey
	publicKey    publicKey
	publicDomain publicDomain
}

func (key *privateKey) sign(message []byte) signature {
	var sig signature
	tmp := ed25519.Sign(ed25519.PrivateKey(key[:]), message)
	copy(sig[:], tmp)
	return sig
}

func (key *publicKey) verify(message []byte, sig *signature) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]), message, sig[:])
}

func (domain publicDomain) equal(comparedDomain publicDomain) bool {
	return domain == comparedDomain
}

func (domain publicDomain) addr() types.Addr {
	return types.Addr(domain[:])
}

func (c *crypto) init(secret ed25519.PrivateKey, domain types.Domain) {
	copy(c.privateKey[:], secret)
	copy(c.publicKey[:], secret.Public().(ed25519.PublicKey))
	copy(c.publicDomain[:], domain)
}
