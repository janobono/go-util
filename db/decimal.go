package db

import (
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5/pgtype"
)

func RatToNumeric(r *big.Rat, scale int) (pgtype.Numeric, error) {
	if r == nil {
		return pgtype.Numeric{Valid: false}, nil
	}
	var n pgtype.Numeric
	s := r.FloatString(max(scale, 0))
	if err := n.Scan(s); err != nil {
		return pgtype.Numeric{}, err
	}
	return n, nil
}

func NumericToRat(n pgtype.Numeric) (*big.Rat, error) {
	if !n.Valid {
		return nil, nil
	}
	v, err := n.Value()
	if err != nil {
		return nil, err
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected numeric value type %T", v)
	}
	r := new(big.Rat)
	if _, ok := r.SetString(s); !ok {
		return nil, fmt.Errorf("invalid numeric string: %q", s)
	}
	return r, nil
}
