package security

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type mockPrincipal struct {
	ID          string
	Authorities []string
}

type mockGrpcTokenInterceptorService struct {
	AuthNotRequiredFunc  func(fullMethod string) bool
	AuthzNotRequiredFunc func(fullMethod string) bool
	IsAuthorizedFunc     func(fullMethod string, principal mockPrincipal) bool
	GetPrincipalFunc     func(tokenType AuthTokenType, token string) (mockPrincipal, error)
}

func (m mockGrpcTokenInterceptorService) AuthenticationNotRequired(fullMethod string) bool {
	if m.AuthNotRequiredFunc == nil {
		return false
	}
	return m.AuthNotRequiredFunc(fullMethod)
}

func (m mockGrpcTokenInterceptorService) AuthorizationNotRequired(fullMethod string) bool {
	if m.AuthzNotRequiredFunc == nil {
		return false
	}
	return m.AuthzNotRequiredFunc(fullMethod)
}

func (m mockGrpcTokenInterceptorService) IsAuthorized(fullMethod string, principal mockPrincipal) bool {
	if m.IsAuthorizedFunc == nil {
		return true
	}
	return m.IsAuthorizedFunc(fullMethod, principal)
}

func (m mockGrpcTokenInterceptorService) GetPrincipal(tokenType AuthTokenType, token string) (mockPrincipal, error) {
	if m.GetPrincipalFunc == nil {
		return mockPrincipal{}, nil
	}
	return m.GetPrincipalFunc(tokenType, token)
}

func fakeHandler(ctx context.Context, req any) (any, error) {
	return "ok", nil
}

func makeAssertingHandler(t *testing.T, wantType AuthTokenType, wantToken string, wantPrincipal mockPrincipal) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		gotType, ok := ContextAuthTokenType(ctx)
		require.True(t, ok, "expected auth token type in context")
		assert.Equal(t, wantType, gotType)

		gotToken, ok := ContextAuthToken(ctx)
		require.True(t, ok, "expected auth token in context")
		assert.Equal(t, wantToken, gotToken)

		gotPrincipal, ok := ContextPrincipal[mockPrincipal](ctx)
		require.True(t, ok, "expected principal in context")
		assert.Equal(t, wantPrincipal, gotPrincipal)

		return "ok", nil
	}
}

func TestGrpcTokenInterceptor_AuthNotRequired_SkipsEverything(t *testing.T) {
	svc := mockGrpcTokenInterceptorService{
		AuthNotRequiredFunc: func(fullMethod string) bool { return true },
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (mockPrincipal, error) {
			t.Fatal("GetPrincipal must not be called when auth is not required")
			return mockPrincipal{}, nil
		},
		IsAuthorizedFunc: func(fullMethod string, principal mockPrincipal) bool {
			t.Fatal("IsAuthorized must not be called when auth is not required")
			return true
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Public"}

	resp, err := interceptor.InterceptAuthToken()(context.Background(), nil, info, fakeHandler)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestGrpcTokenInterceptor_MissingMetadata_Unauthenticated(t *testing.T) {
	svc := mockGrpcTokenInterceptorService{}
	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Secured"}

	_, err := interceptor.InterceptAuthToken()(context.Background(), nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGrpcTokenInterceptor_MissingAuthorization_Unauthenticated(t *testing.T) {
	svc := mockGrpcTokenInterceptorService{}
	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(nil)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Secured"}

	_, err := interceptor.InterceptAuthToken()(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGrpcTokenInterceptor_MultipleAuthorizationHeaders_Unauthenticated(t *testing.T) {
	svc := mockGrpcTokenInterceptorService{}
	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Bearer a"})
	md.Append("authorization", "Bearer b")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Secured"}

	_, err := interceptor.InterceptAuthToken()(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGrpcTokenInterceptor_InvalidAuthorizationScheme_Unauthenticated(t *testing.T) {
	svc := mockGrpcTokenInterceptorService{}
	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Token abc"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Secured"}

	_, err := interceptor.InterceptAuthToken()(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGrpcTokenInterceptor_EmptyToken_Unauthenticated(t *testing.T) {
	svc := mockGrpcTokenInterceptorService{}
	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Bearer     "})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Secured"}

	_, err := interceptor.InterceptAuthToken()(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGrpcTokenInterceptor_ValidBearerToken_SetsContext_Allows(t *testing.T) {
	wantPrincipal := mockPrincipal{ID: "123", Authorities: []string{"ADMIN"}}

	svc := mockGrpcTokenInterceptorService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (mockPrincipal, error) {
			assert.Equal(t, BearerToken, tokenType)
			assert.Equal(t, "token123", token)
			return wantPrincipal, nil
		},
		IsAuthorizedFunc: func(fullMethod string, principal mockPrincipal) bool {
			assert.Equal(t, "/test.Service/Test", fullMethod)
			assert.Equal(t, wantPrincipal, principal)
			return true
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Bearer token123"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	resp, err := interceptor.InterceptAuthToken()(ctx, nil, info, makeAssertingHandler(t, BearerToken, "token123", wantPrincipal))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestGrpcTokenInterceptor_BearerScheme_CaseInsensitive(t *testing.T) {
	wantPrincipal := mockPrincipal{ID: "x"}

	svc := mockGrpcTokenInterceptorService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (mockPrincipal, error) {
			assert.Equal(t, BearerToken, tokenType)
			assert.Equal(t, "token123", token)
			return wantPrincipal, nil
		},
		IsAuthorizedFunc: func(fullMethod string, principal mockPrincipal) bool { return true },
	}

	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	// lower-case scheme should still work
	md := metadata.New(map[string]string{"authorization": "bearer token123"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	resp, err := interceptor.InterceptAuthToken()(ctx, nil, info, makeAssertingHandler(t, BearerToken, "token123", wantPrincipal))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestGrpcTokenInterceptor_ValidBasicToken_SetsContext_Allows(t *testing.T) {
	wantPrincipal := mockPrincipal{ID: "u1"}

	svc := mockGrpcTokenInterceptorService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (mockPrincipal, error) {
			assert.Equal(t, BasicToken, tokenType)
			assert.Equal(t, "dXNlcjpwYXNz", token)
			return wantPrincipal, nil
		},
		IsAuthorizedFunc: func(fullMethod string, principal mockPrincipal) bool { return true },
	}

	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Basic dXNlcjpwYXNz"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	resp, err := interceptor.InterceptAuthToken()(ctx, nil, info, makeAssertingHandler(t, BasicToken, "dXNlcjpwYXNz", wantPrincipal))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestGrpcTokenInterceptor_InvalidToken_Unauthenticated(t *testing.T) {
	svc := mockGrpcTokenInterceptorService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (mockPrincipal, error) {
			return mockPrincipal{}, errors.New("bad token")
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Bearer bad"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptAuthToken()(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGrpcTokenInterceptor_AuthzNotRequired_SkipsIsAuthorized(t *testing.T) {
	wantPrincipal := mockPrincipal{ID: "x"}

	svc := mockGrpcTokenInterceptorService{
		AuthzNotRequiredFunc: func(fullMethod string) bool { return true },
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (mockPrincipal, error) {
			return wantPrincipal, nil
		},
		IsAuthorizedFunc: func(fullMethod string, principal mockPrincipal) bool {
			t.Fatal("IsAuthorized must not be called when authorization is not required")
			return true
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Bearer token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	resp, err := interceptor.InterceptAuthToken()(ctx, nil, info, makeAssertingHandler(t, BearerToken, "token", wantPrincipal))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestGrpcTokenInterceptor_NotAuthorized_PermissionDenied(t *testing.T) {
	wantPrincipal := mockPrincipal{ID: "x"}

	svc := mockGrpcTokenInterceptorService{
		GetPrincipalFunc: func(tokenType AuthTokenType, token string) (mockPrincipal, error) {
			return wantPrincipal, nil
		},
		IsAuthorizedFunc: func(fullMethod string, principal mockPrincipal) bool {
			return false
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockPrincipal](svc)

	md := metadata.New(map[string]string{"authorization": "Bearer token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptAuthToken()(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestContextHelpers_NotFound(t *testing.T) {
	ctx := context.Background()

	tt, ok := ContextAuthTokenType(ctx)
	assert.False(t, ok)
	assert.Equal(t, UnknownToken, tt)

	token, ok := ContextAuthToken(ctx)
	assert.False(t, ok)
	assert.Equal(t, "", token)

	p, ok := ContextPrincipal[mockPrincipal](ctx)
	assert.False(t, ok)
	assert.Equal(t, mockPrincipal{}, p)
}

func TestContextHelpers_WrongType(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, authTokenTypeKey, "bearer") // wrong type (string, not AuthTokenType)
	ctx = context.WithValue(ctx, authTokenKey, 123)          // wrong type (int, not string)
	ctx = context.WithValue(ctx, principalKey, "oops")       // wrong type

	tt, ok := ContextAuthTokenType(ctx)
	assert.False(t, ok)
	assert.Equal(t, UnknownToken, tt)

	token, ok := ContextAuthToken(ctx)
	assert.False(t, ok)
	assert.Equal(t, "", token)

	p, ok := ContextPrincipal[mockPrincipal](ctx)
	assert.False(t, ok)
	assert.Equal(t, mockPrincipal{}, p)
}
