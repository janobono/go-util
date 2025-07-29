package security

import (
	"fmt"
	"math/big"
	"strings"

	crypto "crypto/rand"
)

type RandomString struct {
	Characters string
	Length     int
}

func (rs *RandomString) Generate() (string, error) {
	var builder strings.Builder
	builder.Grow(rs.Length)
	for i := 0; i < rs.Length; i++ {
		num, err := crypto.Int(crypto.Reader, big.NewInt(int64(len(rs.Characters))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random string: %w", err)
		}
		builder.WriteByte(rs.Characters[num.Int64()])
	}
	return builder.String(), nil
}
