package types

import (
	"encoding/hex"
)

// Addr implements the `net.Addr` interface for `Domain` values.
type Addr Domain

// Network returns "Domain" as a string, but is otherwise unused.
func (a Addr) Network() string {
	return "Domain"
}

// String returns the Domain as a hexidecimal string, but is otherwise unused.
func (a Addr) String() string {
	return hex.EncodeToString(a[:])
}
