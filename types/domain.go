package types

import (
	"bytes"
	"crypto/ed25519"
	"strings"
)

//Domain type for the Mesh

type Domain struct {
	Name []byte
	Key  ed25519.PublicKey
}

func (a Domain) Equal(comparedDomain Domain) bool {
	return bytes.Equal(a.Name, comparedDomain.Name) // && a.Key.Equal(comparedDomain.Key)
}

func NewDomain(name string, key ed25519.PublicKey) Domain {
	n := strings.ToLower(name)
	return Domain{
		Key:  key,
		Name: append([]byte(n), make([]byte, ed25519.PublicKeySize-len([]byte(n)))...),
	}
}

func (a Domain) GetNormalizedName() []byte {
	return truncateZeroBytes(a.Name)
}

func truncateZeroBytes(data []byte) []byte {
	length := len(data)
	for length > 0 && data[length-1] == 0 {
		length--
	}
	return data[:length]
}
