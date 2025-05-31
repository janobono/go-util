package security

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestEncodeAndComparePassword(t *testing.T) {
	encoder := NewPasswordEncoder(bcrypt.DefaultCost)

	password := "securePassword123!"

	// Encode the password
	hashed, err := encoder.Encode(password)
	if err != nil {
		t.Fatalf("unexpected error during Encode: %v", err)
	}

	// The hash should not be equal to the original password
	if hashed == password {
		t.Error("encoded password should not equal the original password")
	}

	// Compare should succeed
	if err := encoder.Compare(password, hashed); err != nil {
		t.Errorf("expected passwords to match, got error: %v", err)
	}

	// Compare should fail with incorrect password
	wrongPassword := "wrongPassword"
	if err := encoder.Compare(wrongPassword, hashed); err == nil {
		t.Error("expected comparison to fail with wrong password, but it succeeded")
	}
}

func TestInvalidCostFallsBackToDefault(t *testing.T) {
	encoder := NewPasswordEncoder(999) // invalid cost

	if encoder.cost != bcrypt.DefaultCost {
		t.Errorf("expected default cost %d, got %d", bcrypt.DefaultCost, encoder.cost)
	}
}
