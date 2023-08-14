package types

import (
	"bytes"
	"crypto/ed25519"
)

//Domain type for the Mesh

type Domain struct {
	Name []byte
	Key  ed25519.PublicKey
}

func (a Domain) Equal(comparedDomain Domain) bool {
	return bytes.Equal(a.Name, comparedDomain.Name) && a.Key.Equal(comparedDomain.Key)
}

func NewDomain(name string, key ed25519.PublicKey) Domain {
	return Domain{
		Key:  key,
		Name: append([]byte(name), make([]byte, ed25519.PublicKeySize-len([]byte(name)))...),
	}
}
