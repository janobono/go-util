package security

import (
	"strings"
	"testing"
)

func TestRandomStringGenerate(t *testing.T) {
	rs := RandomString{
		Characters: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		Length:     16,
	}

	// Generate first string
	str1, err := rs.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check length
	if len(str1) != rs.Length {
		t.Errorf("expected length %d, got %d", rs.Length, len(str1))
	}

	// Check allowed characters
	for _, ch := range str1 {
		if !strings.ContainsRune(rs.Characters, ch) {
			t.Errorf("generated string contains invalid character: %q", ch)
		}
	}

	// Generate second string
	str2, err := rs.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check randomness (should not be identical)
	if str1 == str2 {
		t.Errorf("two generated strings are identical: %s", str1)
	}
}
