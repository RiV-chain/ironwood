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
type privateKey [privateKeySize]byte
type signature [signatureSize]byte

type crypto struct {
	privateKey privateKey
	publicKey  publicDomain
}

func (key *privateKey) sign(message []byte) signature {
	var sig signature
	tmp := ed25519.Sign(ed25519.PrivateKey(key[:]), message)
	copy(sig[:], tmp)
	return sig
}

func (key privateKey) equal(comparedKey privateKey) bool {
	return key == comparedKey
}

func (key *publicDomain) verify(message []byte, sig *signature) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]), message, sig[:])
}

func (key publicDomain) equal(comparedKey publicDomain) bool {
	return key == comparedKey
}

func (key publicDomain) addr() types.Addr {
	return types.Addr(key[:])
}

func (c *crypto) init(secret ed25519.PrivateKey) {
	copy(c.privateKey[:], secret)
	copy(c.publicKey[:], secret.Public().(ed25519.PublicKey))
}
