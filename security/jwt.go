package security

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type GetPublicKey func(ctx context.Context, kid string) (interface{}, error)

type JwtToken struct {
	algorithm       *jwt.SigningMethodRSA
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	kid             string
	issuer          string
	tokenExpiration time.Duration
	keyExpiration   time.Time
	getPublicKey    GetPublicKey
}

func NewJwtToken(
	algorithm *jwt.SigningMethodRSA,
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	kid string,
	issuer string,
	tokenExpiration time.Duration,
	keyExpiration time.Time,
	getPublicKey GetPublicKey,
) *JwtToken {
	return &JwtToken{
		algorithm:       algorithm,
		privateKey:      privateKey,
		publicKey:       publicKey,
		kid:             kid,
		issuer:          issuer,
		tokenExpiration: tokenExpiration,
		keyExpiration:   keyExpiration,
		getPublicKey:    getPublicKey,
	}
}

func (t *JwtToken) KeyID() string {
	return t.kid
}

func (t *JwtToken) TokenExpiration() time.Duration {
	return t.tokenExpiration
}

func (t *JwtToken) KeyExpiration() time.Time {
	return t.keyExpiration
}

func (t *JwtToken) GenerateToken(claims jwt.MapClaims) (string, error) {
	now := time.Now().UTC()

	jwtClaims := jwt.MapClaims{
		"iss": t.issuer,
		"iat": now.Unix(),
		"exp": now.Add(t.tokenExpiration).Unix(),
	}

	for k, v := range claims {
		jwtClaims[k] = v
	}

	token := jwt.NewWithClaims(t.algorithm, jwtClaims)
	token.Header["kid"] = t.kid
	signedToken, err := token.SignedString(t.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func (t *JwtToken) ParseToken(ctx context.Context, tokenString string) (*jwt.MapClaims, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return t.getKeyFunc(ctx, token)
	}

	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("error getting issuer: %w", err)
	}

	if issuer != t.issuer {
		return nil, errors.New("invalid issuer")
	}

	return &claims, nil
}

func (t *JwtToken) getKeyFunc(ctx context.Context, token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"].(string)

	if !ok {
		return nil, fmt.Errorf("missing or invalid kid in header")
	}

	if kid != t.kid {
		return t.getPublicKey(ctx, kid)
	}

	return t.publicKey, nil
}
