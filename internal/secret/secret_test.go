package secret

import (
	"strings"
	"testing"
)

// Every identifier and credential in Clerk is unguessable random material.
// Collisions or predictability here would undermine the whole provider.
func TestTokenIsRandomAndURLSafe(t *testing.T) {
	const samples = 250

	seen := make(map[string]bool, samples)
	for range samples {
		got, err := Token(32)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}
		if seen[got] {
			t.Fatalf("Token() returned a duplicate value %q", got)
		}
		seen[got] = true

		// base64url without padding: safe in URLs, form fields and headers.
		if strings.ContainsAny(got, "+/=") {
			t.Errorf("Token() = %q, want base64url without padding", got)
		}
		if len(got) < 40 {
			t.Errorf("Token() = %q (%d chars), too short for 32 bytes", got, len(got))
		}
	}
}

func TestTokenRejectsWeakLengths(t *testing.T) {
	for _, n := range []int{0, -1, 8} {
		if _, err := Token(n); err == nil {
			t.Errorf("Token(%d) succeeded; want an error for insufficient entropy", n)
		}
	}
}

func TestClientIDAndClientSecretAreDistinctAndStrong(t *testing.T) {
	id, err := NewClientID()
	if err != nil {
		t.Fatalf("NewClientID() error: %v", err)
	}
	sec, err := NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret() error: %v", err)
	}

	if id == sec {
		t.Fatal("client id and client secret are identical")
	}
	// The secret authenticates the client, so it carries the most entropy.
	if len(sec) < len(id) {
		t.Errorf("client secret (%d chars) is weaker than the client id (%d chars)", len(sec), len(id))
	}
}

func TestHashSecretVerifies(t *testing.T) {
	const plain = "s3cret-value"

	hash, err := HashSecret(plain)
	if err != nil {
		t.Fatalf("HashSecret() error: %v", err)
	}

	// The stored hash must not reveal the secret.
	if strings.Contains(hash, plain) {
		t.Error("the stored hash contains the plaintext secret")
	}
	if !VerifySecret(hash, plain) {
		t.Error("VerifySecret() rejected the correct secret")
	}
	if VerifySecret(hash, "wrong-value") {
		t.Error("VerifySecret() accepted an incorrect secret")
	}
	if VerifySecret("not-a-hash", plain) {
		t.Error("VerifySecret() accepted a malformed hash")
	}
}

// bcrypt salts each hash, so the same input must never produce the same digest.
func TestHashSecretIsSalted(t *testing.T) {
	a, err := HashSecret("same-input")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashSecret("same-input")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two hashes of the same secret are identical; the hash is unsalted")
	}
}

// bcrypt silently ignores input past 72 bytes, which would make two different
// long secrets interchangeable. Reject rather than truncate.
func TestHashSecretRejectsOverlongInput(t *testing.T) {
	if _, err := HashSecret(strings.Repeat("a", 73)); err == nil {
		t.Error("HashSecret() accepted input longer than bcrypt's 72-byte limit")
	}
}

func TestHashSecretRejectsEmptyInput(t *testing.T) {
	if _, err := HashSecret(""); err == nil {
		t.Error("HashSecret() accepted an empty secret")
	}
}

// Authorization codes and access tokens are high-entropy random values, so a
// fast digest is the right tool: it makes a stolen database dump unusable for
// replay without putting a bcrypt cost on every token validation.
func TestHashTokenIsDeterministicAndOpaque(t *testing.T) {
	const tok = "an-access-token"

	first := HashToken(tok)
	if first != HashToken(tok) {
		t.Error("HashToken() is not deterministic; stored tokens could never be looked up")
	}
	if first == HashToken("another-token") {
		t.Error("HashToken() collided on different inputs")
	}
	if strings.Contains(first, tok) {
		t.Error("HashToken() output contains the token itself")
	}
	if strings.ContainsAny(first, "+/=") {
		t.Errorf("HashToken() = %q, want base64url without padding", first)
	}
}
