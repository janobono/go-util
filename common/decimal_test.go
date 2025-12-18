package common

import (
	"math/big"
	"testing"
)

func mustRat(t *testing.T, s string) *big.Rat {
	t.Helper()
	r := new(big.Rat)
	if _, ok := r.SetString(s); !ok {
		t.Fatalf("bad rat literal: %q", s)
	}
	return r
}

func assertRatEq(t *testing.T, got *big.Rat, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("got nil, want %q", want)
	}
	w := new(big.Rat)
	if _, ok := w.SetString(want); !ok {
		t.Fatalf("bad want literal: %q", want)
	}
	if got.Cmp(w) != 0 {
		t.Fatalf("got %s want %s", got.RatString(), w.RatString())
	}
}

func TestRescale_RoundHalfUp_PositiveScale(t *testing.T) {
	tests := []struct {
		in    string
		scale int
		want  string
	}{
		{"123.456", 2, "123.46"},
		{"123.454", 2, "123.45"},
		{"123.455", 2, "123.46"}, // tie goes away from zero
		{"1.005", 2, "1.01"},
		{"0.000", 2, "0.00"},
	}

	for _, tc := range tests {
		got := Rescale(mustRat(t, tc.in), tc.scale, RoundHalfUp)
		assertRatEq(t, got, tc.want)
	}
}

func TestRescale_RoundHalfUp_NegativeNumbers(t *testing.T) {
	tests := []struct {
		in    string
		scale int
		want  string
	}{
		{"-123.456", 2, "-123.46"},
		{"-123.454", 2, "-123.45"},
		{"-123.455", 2, "-123.46"}, // tie goes away from zero
		{"-1.005", 2, "-1.01"},
	}

	for _, tc := range tests {
		got := Rescale(mustRat(t, tc.in), tc.scale, RoundHalfUp)
		assertRatEq(t, got, tc.want)
	}
}

func TestRescale_RoundHalfUp_ScaleZero(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"123.4", "123"},
		{"123.5", "124"},
		{"-123.5", "-124"},
		{"-123.4", "-123"},
	}

	for _, tc := range tests {
		got := Rescale(mustRat(t, tc.in), 0, RoundHalfUp)
		assertRatEq(t, got, tc.want)
	}
}

func TestRescale_RoundUp(t *testing.T) {
	tests := []struct {
		in    string
		scale int
		want  string
	}{
		// scale = 0 (BigDecimal UP => away from zero)
		{"0.0", 0, "0"},
		{"0.1", 0, "1"},
		{"0.9", 0, "1"},
		{"-0.1", 0, "-1"},
		{"-0.9", 0, "-1"},

		// scale = 1
		{"1.00", 1, "1.0"},
		{"1.01", 1, "1.1"},
		{"-1.00", 1, "-1.0"},
		{"-1.01", 1, "-1.1"},

		// scale = 2
		{"1.230", 2, "1.23"},
		{"1.231", 2, "1.24"},
		{"-1.230", 2, "-1.23"},
		{"-1.231", 2, "-1.24"},
	}

	for _, tc := range tests {
		got := Rescale(mustRat(t, tc.in), tc.scale, RoundUp)
		assertRatEq(t, got, tc.want)
	}
}

func TestRescale_PanicsOnNegativeScale(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for negative scale, got none")
		}
	}()
	_ = Rescale(mustRat(t, "123.1"), -1, RoundHalfUp)
}

func TestToRat_ReturnsErrorOnNegativeScale(t *testing.T) {
	_, err := ToRat(12.345, -1, RoundHalfUp)
	if err == nil {
		t.Fatalf("expected error for negative scale, got nil")
	}
}

func TestToRat_RescalesFloatInput(t *testing.T) {
	got, err := ToRat(12.345, 2, RoundHalfUp)
	if err != nil {
		t.Fatalf("ToRat error: %v", err)
	}
	assertRatEq(t, got, "12.35")
}
