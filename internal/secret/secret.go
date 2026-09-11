// Package secret generates and protects the random material Clerk relies on:
// client identifiers, client secrets, subject identifiers, authorization codes
// and access tokens.
//
// Two kinds of hashing live here deliberately. Client secrets are bcrypt-hashed
// because they are long-lived credentials. Authorization codes and access
// tokens are SHA-256 hashed instead: they are already high-entropy random
// values, so a fast digest makes a stolen database dump useless for replay
// without putting a bcrypt cost on every single token validation.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	// minTokenBytes is the smallest amount of entropy any generated value may
	// carry. 16 bytes (128 bits) is the floor for an unguessable identifier.
	minTokenBytes = 16

	// clientIDBytes identifies a client; it is public and need not resist
	// offline attack, only collision and guessing.
	clientIDBytes = 16

	// clientSecretBytes authenticates a client, so it carries more entropy.
	clientSecretBytes = 32

	// bcryptMaxInputBytes is bcrypt's hard input limit. Anything beyond it is
	// silently ignored by the algorithm, which would make two different long
	// secrets interchangeable.
	bcryptMaxInputBytes = 72
)

// Token returns n bytes of cryptographically secure randomness, base64url
// encoded without padding so it is safe in URLs, form fields and headers.
func Token(n int) (string, error) {
	if n < minTokenBytes {
		return "", fmt.Errorf("refusing to generate a %d-byte token; need at least %d bytes of entropy", n, minTokenBytes)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewClientID returns a fresh, unguessable client identifier. It is generated
// by the provider and is never user-editable.
func NewClientID() (string, error) { return Token(clientIDBytes) }

// NewClientSecret returns a fresh client secret. The caller must show it to the
// administrator once and store only its hash.
func NewClientSecret() (string, error) { return Token(clientSecretBytes) }

// HashSecret returns a bcrypt hash suitable for storage.
func HashSecret(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("refusing to hash an empty secret")
	}
	if len(plain) > bcryptMaxInputBytes {
		return "", fmt.Errorf("secret is %d bytes, exceeding bcrypt's %d-byte limit (the excess would be silently ignored)", len(plain), bcryptMaxInputBytes)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash secret: %w", err)
	}
	return string(h), nil
}

// VerifySecret reports whether plain matches the stored hash. bcrypt's
// comparison is constant-time with respect to the digest.
func VerifySecret(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// HashToken returns the stored form of an authorization code or access token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
