package types

import (
	"encoding/hex"
)

// Addr implements the `net.Addr` interface for `ed25519.PublicKey` or `Domain` values.
type Addr []byte

// Network returns "address" as a string, but is otherwise unused.
func (a Addr) Network() string {
	return "address"
}

// String returns the ed25519.PublicKey or Domain as a hexidecimal string, but is otherwise unused.
func (a Addr) String() string {
	return hex.EncodeToString(a)
}
