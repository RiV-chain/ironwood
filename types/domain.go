package types

import "crypto/ed25519"

// Domain in the mesh.
type Domain [ed25519.PublicKeySize]byte
