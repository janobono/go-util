package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestJwt(t *testing.T) {
	jwtToken := initJwtToken(t, 60)

	token, err := jwtToken.GenerateToken(jwt.MapClaims{"data": "test data"})
	if err != nil {
		t.Fatalf("Error generating token: %s", err)
	}

	t.Logf("Generated Token: %s", token)

	parsedToken, err := jwtToken.ParseToken(context.Background(), token)
	if err != nil {
		t.Fatalf("Error parsing token: %s", err)
	}
	assert.Equal(t, "test data", (*parsedToken)["data"])
}

func TestJwtExpired(t *testing.T) {
	jwtToken := initJwtToken(t, 0)

	token, err := jwtToken.GenerateToken(jwt.MapClaims{"data": "test data"})
	if err != nil {
		t.Fatalf("Error generating token: %s", err)
	}

	t.Logf("Generated Token: %s", token)

	time.Sleep(100 * time.Millisecond)

	_, err = jwtToken.ParseToken(context.Background(), token)

	assert.ErrorContains(t, err, "token is expired")
}

func TestJwtSignature(t *testing.T) {
	jwtToken1 := initJwtToken(t, 60)
	jwtToken2 := initJwtToken(t, 60)

	token, err := jwtToken1.GenerateToken(jwt.MapClaims{"data": "test data"})
	if err != nil {
		t.Fatalf("Error generating token: %s", err)
	}

	t.Logf("Generated Token: %s", token)

	_, err = jwtToken2.ParseToken(context.Background(), token)

	assert.ErrorContains(t, err, "verification error")
}

// initJwtToken creates a JwtToken instance for testing
func initJwtToken(t *testing.T, expiration int64) *JwtToken {
	algorithm := jwt.SigningMethodRS256
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating private key: %s", err)
	}
	publicKey := &privateKey.PublicKey

	jwtToken := NewJwtToken(
		algorithm,
		privateKey,
		publicKey,
		"kid",
		"test",
		time.Duration(expiration)*time.Second,
		time.Now().Add(1*time.Hour),
		func(ctx context.Context, kid string) (interface{}, error) {
			return nil, fmt.Errorf("not implemented") // not used because the same key is embedded
		},
	)

	return jwtToken
}
