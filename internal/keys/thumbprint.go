package keys

import (
	"crypto"
	"encoding/base64"

	// Registers SHA-256 for crypto.SHA256.New, used by the JWK thumbprint.
	_ "crypto/sha256"
)

// defaultThumbprintHash is the hash RFC 7638 thumbprints are computed with.
const defaultThumbprintHash = crypto.SHA256

// base64url encodes without padding, matching the JOSE conventions used for
// "kid" values.
func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
