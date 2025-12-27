package security

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type httpPrincipal struct {
	ID string
}

type mockPrincipalService struct {
	GetPrincipalFunc func(tokenType AuthTokenType, token string) (httpPrincipal, error)
}

func (m mockPrincipalService) GetPrincipal(ctx context.Context, tokenType AuthTokenType, token string) (httpPrincipal, error) {
	if m.GetPrincipalFunc == nil {
		return httpPrincipal{}, nil
	}
	return m.GetPrincipalFunc(tokenType, token)
}

type mockHttpAuthzService struct {
	GetPrincipalFunc func(ctx context.Context, tokenType AuthTokenType, token string) (httpPrincipal, error)
	IsAuthorizedFunc func(principal httpPrincipal) bool
}

func (m mockHttpAuthzService) GetPrincipal(ctx context.Context, tokenType AuthTokenType, token string) (httpPrincipal, error) {
	if m.GetPrincipalFunc == nil {
		return httpPrincipal{}, nil
	}
	return m.GetPrincipalFunc(ctx, tokenType, token)
}

func (m mockHttpAuthzService) IsAuthorized(principal httpPrincipal) bool {
	if m.IsAuthorizedFunc == nil {
		return true
	}
	return m.IsAuthorizedFunc(principal)
}

func TestHttpAuthMiddleware_Unauthorized_WhenMissingAuthorizationHeader(t *testing.T) {
	mw := NewHttpRestTokenAuthenticationMiddleware[httpPrincipal](mockPrincipalService{})
	nextCalled := false

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()

	mw.RequireAuthentication(next).ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHttpAuthMiddleware_Unauthorized_WhenInvalidScheme(t *testing.T) {
	mw := NewHttpRestTokenAuthenticationMiddleware[httpPrincipal](mockPrincipalService{})
	nextCalled := false

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Token abc")
	rr := httptest.NewRecorder()

	mw.RequireAuthentication(next).ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHttpAuthMiddleware_Unauthorized_WhenEmptyToken(t *testing.T) {
	mw := NewHttpRestTokenAuthenticationMiddleware[httpPrincipal](mockPrincipalService{})
	nextCalled := false

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// With your parseToken, "Bearer   " becomes invalid scheme (len(parts)!=2) -> err
	req.Header.Set("Authorization", "Bearer   ")
	rr := httptest.NewRecorder()

	mw.RequireAuthentication(next).ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHttpAuthMiddleware_Unauthorized_WhenGetPrincipalFails(t *testing.T) {
	mw := NewHttpRestTokenAuthenticationMiddleware[httpPrincipal](mockPrincipalService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (httpPrincipal, error) {
			return httpPrincipal{}, errors.New("invalid token")
		},
	})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer token123")
	rr := httptest.NewRecorder()

	mw.RequireAuthentication(next).ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHttpAuthMiddleware_OK_SetsContextAndCallsNext_Bearer(t *testing.T) {
	wantPrincipal := httpPrincipal{ID: "p1"}

	mw := NewHttpRestTokenAuthenticationMiddleware[httpPrincipal](mockPrincipalService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (httpPrincipal, error) {
			assert.Equal(t, BearerToken, tokenType)
			assert.Equal(t, "token123", token)
			return wantPrincipal, nil
		},
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tt, ok := ContextAuthTokenType(r.Context())
		require.True(t, ok)
		assert.Equal(t, BearerToken, tt)

		tok, ok := ContextAuthToken(r.Context())
		require.True(t, ok)
		assert.Equal(t, "token123", tok)

		p, ok := ContextPrincipal[httpPrincipal](r.Context())
		require.True(t, ok)
		assert.Equal(t, wantPrincipal, p)

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer token123")
	rr := httptest.NewRecorder()

	mw.RequireAuthentication(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHttpAuthMiddleware_OK_SchemeIsCaseInsensitive(t *testing.T) {
	mw := NewHttpRestTokenAuthenticationMiddleware[httpPrincipal](mockPrincipalService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (httpPrincipal, error) {
			assert.Equal(t, BearerToken, tokenType)
			assert.Equal(t, "token123", token)
			return httpPrincipal{ID: "x"}, nil
		},
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "bearer token123")
	rr := httptest.NewRecorder()

	mw.RequireAuthentication(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHttpAuthzMiddleware_Unauthorized_WhenNoPrincipalInContext(t *testing.T) {
	authz := NewHttpRestTokenAuthorizationMiddleware[httpPrincipal](mockHttpAuthzService{
		IsAuthorizedFunc: func(principal httpPrincipal) bool {
			t.Fatal("IsAuthorized must not be called when principal is missing")
			return true
		},
	})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()

	authz.RequireAuthorization(next).ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHttpAuthzMiddleware_Forbidden_WhenNotAuthorized(t *testing.T) {
	authz := NewHttpRestTokenAuthorizationMiddleware[httpPrincipal](mockHttpAuthzService{
		IsAuthorizedFunc: func(principal httpPrincipal) bool {
			return false
		},
	})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Seed principal in context (as if auth middleware ran)
	ctx := reqWithPrincipal(t, httpPrincipal{ID: "p1"})
	rr := httptest.NewRecorder()

	authz.RequireAuthorization(next).ServeHTTP(rr, ctx)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHttpAuthzMiddleware_OK_WhenAuthorized(t *testing.T) {
	authz := NewHttpRestTokenAuthorizationMiddleware[httpPrincipal](mockHttpAuthzService{
		IsAuthorizedFunc: func(principal httpPrincipal) bool {
			return principal.ID == "p1"
		},
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := reqWithPrincipal(t, httpPrincipal{ID: "p1"})
	rr := httptest.NewRecorder()

	authz.RequireAuthorization(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// helper: builds a request with principal in context
func reqWithPrincipal(t *testing.T, p httpPrincipal) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctx := req.Context()
	ctx = contextWithPrincipal(ctx, p)
	return req.WithContext(ctx)
}

// helper: write principal into context using the same key as middleware
func contextWithPrincipal(ctx context.Context, p httpPrincipal) context.Context {
	ctx = context.WithValue(ctx, principalKey, p)
	return ctx
}
