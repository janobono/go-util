package security

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
)

type PasswordEncoder struct {
	cost int
}

func NewPasswordEncoder(cost int) *PasswordEncoder {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		slog.Warn("Invalid bcrypt cost",
			slog.Int("provided", cost),
			slog.Int("using_default", bcrypt.DefaultCost),
		)
		cost = bcrypt.DefaultCost
	}
	return &PasswordEncoder{cost}
}

func (p *PasswordEncoder) Encode(password string) (string, error) {
	encodedPassword, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt password: %w", err)
	}
	return string(encodedPassword), nil
}

func (p *PasswordEncoder) Compare(password, encodedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(encodedPassword), []byte(password))
}
