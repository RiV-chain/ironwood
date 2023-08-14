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
