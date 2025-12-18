package db

import (
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func mustRat(t *testing.T, s string) *big.Rat {
	t.Helper()
	r := new(big.Rat)
	if _, ok := r.SetString(s); !ok {
		t.Fatalf("bad rat literal: %q", s)
	}
	return r
}

func TestRatToNumeric_And_Back_RoundTrip(t *testing.T) {
	r := mustRat(t, "123.456789")

	n, err := RatToNumeric(r, 6)
	if err != nil {
		t.Fatalf("RatToNumeric error: %v", err)
	}
	if !n.Valid {
		t.Fatalf("numeric should be valid")
	}

	r2, err := NumericToRat(n)
	if err != nil {
		t.Fatalf("NumericToRat error: %v", err)
	}

	// Expect exact 6 scale string form: 123.456789
	want := mustRat(t, "123.456789")
	if r2.Cmp(want) != 0 {
		t.Fatalf("got %s want %s", r2.RatString(), want.RatString())
	}
}

func TestNumericToRat_Null(t *testing.T) {
	r, err := NumericToRat(pgtype.Numeric{Valid: false})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil rat for invalid numeric")
	}
}

func TestRatToNumeric_Nil(t *testing.T) {
	n, err := RatToNumeric(nil, 2)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n.Valid {
		t.Fatalf("expected invalid numeric for nil rat")
	}
}
