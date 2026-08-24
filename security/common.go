package security

import (
	"context"
	"errors"
	"strings"
)

type PrincipalService[T any] interface {
	GetPrincipal(ctx context.Context, tokenType AuthTokenType, token string) (T, error)
}

type AuthTokenType string

const (
	UnknownToken AuthTokenType = ""
	BasicToken   AuthTokenType = "basic"
	BearerToken  AuthTokenType = "bearer"
)

type CtxKey struct{ name string }

var (
	AuthTokenTypeKey = CtxKey{"authTokenType"}
	AuthTokenKey     = CtxKey{"authToken"}
	PrincipalKey     = CtxKey{"principal"}
)

func ParseToken(raw string) (AuthTokenType, string, error) {
	parts := strings.SplitN(strings.TrimSpace(raw), " ", 2)
	if len(parts) != 2 {
		return UnknownToken, "", errors.New("invalid authorization scheme")
	}
	scheme, token := parts[0], strings.TrimSpace(parts[1])

	switch {
	case strings.EqualFold(scheme, "Basic"):
		return BasicToken, token, nil
	case strings.EqualFold(scheme, "Bearer"):
		return BearerToken, token, nil
	default:
		return UnknownToken, "", errors.New("invalid authorization scheme")
	}
}

func ContextAuthTokenType(ctx context.Context) (AuthTokenType, bool) {
	value := ctx.Value(AuthTokenTypeKey)
	if value == nil {
		return UnknownToken, false
	}
	typedValue, ok := value.(AuthTokenType)
	return typedValue, ok
}

func ContextAuthToken(ctx context.Context) (string, bool) {
	value := ctx.Value(AuthTokenKey)
	if value == nil {
		return "", false
	}
	typedValue, ok := value.(string)
	return typedValue, ok
}

func ContextPrincipal[T any](ctx context.Context) (T, bool) {
	value := ctx.Value(PrincipalKey)
	if value == nil {
		var zero T
		return zero, false
	}
	typedValue, ok := value.(T)
	return typedValue, ok
}
