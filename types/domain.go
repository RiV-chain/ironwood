package types

import (
	"crypto/ed25519"
	"strings"
)

//Domain type for the Mesh

type Domain struct {
	Name [ed25519.PublicKeySize]byte
	Key  ed25519.PublicKey
}

func (a Domain) Equal(comparedDomain Domain) bool {
	return a.Name == comparedDomain.Name
}

func NewDomain(name string, key ed25519.PublicKey) Domain {
	s := strings.ToLower(name)
	var n [ed25519.PublicKeySize]byte
	copy(n[:], []byte(s))
	return Domain{
		Key:  key,
		Name: n,
	}
}

func (a Domain) GetNormalizedName() []byte {
	return truncateZeroBytes(a.Name[:])
}

func truncateZeroBytes(data []byte) []byte {
	length := len(data)
	for length > 0 && data[length-1] == 0 {
		length--
	}
	return data[:length]
}
