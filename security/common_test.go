package security

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testPrincipal struct {
	ID string
}

func TestParseToken(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantType  AuthTokenType
		wantToken string
		wantErr   bool
	}{
		{
			name:      "bearer ok",
			raw:       "Bearer token123",
			wantType:  BearerToken,
			wantToken: "token123",
		},
		{
			name:      "basic ok",
			raw:       "Basic dXNlcjpwYXNz",
			wantType:  BasicToken,
			wantToken: "dXNlcjpwYXNz",
		},
		{
			name:      "scheme is case-insensitive (bearer)",
			raw:       "bearer token123",
			wantType:  BearerToken,
			wantToken: "token123",
		},
		{
			name:      "scheme is case-insensitive (basic)",
			raw:       "bAsIc abc",
			wantType:  BasicToken,
			wantToken: "abc",
		},
		{
			name:      "trims surrounding whitespace",
			raw:       "   Bearer   token123   ",
			wantType:  BearerToken,
			wantToken: "token123",
		},
		{
			name:      "token may contain spaces after first split (kept, trimmed ends)",
			raw:       "Bearer   a b  c   ",
			wantType:  BearerToken,
			wantToken: "a b  c",
		},
		{
			name:    "invalid: missing space separator",
			raw:     "Bearer",
			wantErr: true,
		},
		{
			name:    "invalid: empty string",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "invalid: unknown scheme",
			raw:     "Token abc",
			wantErr: true,
		},
		{
			name:    "invalid: only whitespace",
			raw:     "   ",
			wantErr: true,
		},
		{
			name:    "invalid: scheme without token",
			raw:     "Bearer   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotToken, err := parseToken(tt.raw)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, UnknownToken, gotType)
				assert.Equal(t, "", gotToken)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantType, gotType)
			assert.Equal(t, tt.wantToken, gotToken)
		})
	}
}

func TestContextAuthTokenType(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		got, ok := ContextAuthTokenType(context.Background())
		assert.False(t, ok)
		assert.Equal(t, UnknownToken, got)
	})

	t.Run("found", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), authTokenTypeKey, BearerToken)
		got, ok := ContextAuthTokenType(ctx)
		assert.True(t, ok)
		assert.Equal(t, BearerToken, got)
	})

	t.Run("wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), authTokenTypeKey, "bearer") // string, not AuthTokenType
		got, ok := ContextAuthTokenType(ctx)
		assert.False(t, ok)
		assert.Equal(t, UnknownToken, got)
	})
}

func TestContextAuthToken(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		got, ok := ContextAuthToken(context.Background())
		assert.False(t, ok)
		assert.Equal(t, "", got)
	})

	t.Run("found", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), authTokenKey, "token123")
		got, ok := ContextAuthToken(ctx)
		assert.True(t, ok)
		assert.Equal(t, "token123", got)
	})

	t.Run("wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), authTokenKey, 123)
		got, ok := ContextAuthToken(ctx)
		assert.False(t, ok)
		assert.Equal(t, "", got)
	})
}

func TestContextPrincipal(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		got, ok := ContextPrincipal[testPrincipal](context.Background())
		assert.False(t, ok)
		assert.Equal(t, testPrincipal{}, got)
	})

	t.Run("found", func(t *testing.T) {
		want := testPrincipal{ID: "p1"}
		ctx := context.WithValue(context.Background(), principalKey, want)
		got, ok := ContextPrincipal[testPrincipal](ctx)
		assert.True(t, ok)
		assert.Equal(t, want, got)
	})

	t.Run("wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), principalKey, "oops")
		got, ok := ContextPrincipal[testPrincipal](ctx)
		assert.False(t, ok)
		assert.Equal(t, testPrincipal{}, got)
	})
}
