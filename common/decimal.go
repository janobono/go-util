package common

import (
	"fmt"
	"math/big"
	"strconv"
)

type RoundingMode int

const (
	RoundHalfUp RoundingMode = iota
	RoundUp
)

func ToRat(f float64, scale int, mode RoundingMode) (*big.Rat, error) {
	if scale < 0 {
		return nil, fmt.Errorf("scale must be >= 0, got %d", scale)
	}

	s := strconv.FormatFloat(f, 'f', -1, 64)
	r := new(big.Rat)
	if _, ok := r.SetString(s); !ok {
		return nil, fmt.Errorf("cannot parse float64 as decimal string: %q", s)
	}
	return Rescale(r, scale, mode), nil
}

func Rescale(value *big.Rat, scale int, mode RoundingMode) *big.Rat {
	if value == nil {
		return nil
	}
	if scale < 0 {
		panic("scale must be >= 0")
	}

	switch mode {
	case RoundUp:
		return roundUp(value, scale)
	case RoundHalfUp:
		return roundHalfUp(value, scale)
	default:
		panic("unsupported rounding mode")
	}
}

func roundHalfUp(r *big.Rat, scale int) *big.Rat {
	// factor = 10^scale
	factorInt := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
	factor := new(big.Rat).SetInt(factorInt)

	// x = r * factor
	x := new(big.Rat).Mul(r, factor)

	// q = floor(x) toward zero (Quo gives truncated toward zero)
	q := new(big.Int).Quo(x.Num(), x.Denom())

	// frac = x - q
	frac := new(big.Rat).Sub(x, new(big.Rat).SetInt(q))

	// For negatives, truncation toward zero means frac is negative or zero.
	// We want HALF_UP "away from zero" when |frac| >= 0.5.
	absFrac := new(big.Rat).Abs(frac)

	if absFrac.Cmp(big.NewRat(1, 2)) >= 0 {
		if x.Sign() >= 0 {
			q.Add(q, big.NewInt(1))
		} else {
			q.Sub(q, big.NewInt(1))
		}
	}

	// result = q / factor
	return new(big.Rat).SetInt(q).Quo(new(big.Rat).SetInt(q), factor)
}

func roundUp(r *big.Rat, scale int) *big.Rat {
	// factor = 10^scale
	factorInt := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
	factor := new(big.Rat).SetInt(factorInt)

	// x = r * factor
	x := new(big.Rat).Mul(r, factor)

	// q = trunc toward zero
	q := new(big.Int).Quo(x.Num(), x.Denom())

	// if there is any fractional part → move away from zero
	rem := new(big.Int).Rem(x.Num(), x.Denom())
	if rem.Sign() != 0 {
		if x.Sign() >= 0 {
			q.Add(q, big.NewInt(1))
		} else {
			q.Sub(q, big.NewInt(1))
		}
	}

	// result = q / factor
	return new(big.Rat).Quo(new(big.Rat).SetInt(q), factor)
}
