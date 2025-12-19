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

type mockGrpcUser struct {
	ID          string
	Authorities []string
}

type mockDecoder struct {
	DecodeFunc      func(tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error)
	AuthoritiesFunc func(user mockGrpcUser) ([]string, error)
}

func (m mockDecoder) DecodeGrpcUserDetail(ctx context.Context, tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error) {
	if m.DecodeFunc == nil {
		return mockGrpcUser{}, nil
	}
	return m.DecodeFunc(tokenType, token)
}

func (m mockDecoder) GetGrpcUserAuthorities(ctx context.Context, user mockGrpcUser) ([]string, error) {
	if m.AuthoritiesFunc != nil {
		return m.AuthoritiesFunc(user)
	}
	return user.Authorities, nil
}

// handler that asserts context values set by interceptor
func makeAssertingHandler(t *testing.T, wantToken string, wantUser mockGrpcUser) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		gotToken, ok := ContextAccessToken(ctx)
		require.True(t, ok, "expected token in context")
		assert.Equal(t, wantToken, gotToken)

		gotUser, ok := ContextUserDetail[mockGrpcUser](ctx)
		require.True(t, ok, "expected user detail in context")
		assert.Equal(t, wantUser, gotUser)

		return "ok", nil
	}
}

func fakeHandler(ctx context.Context, req any) (any, error) {
	return "ok", nil
}

func TestInterceptor_ValidBearerToken(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error) {
			assert.Equal(t, GrpcBearerTokenType, tokenType)
			assert.Equal(t, "token123", token)
			return mockGrpcUser{ID: "123", Authorities: []string{"ADMIN"}}, nil
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)
	methods := []GrpcSecuredMethod{
		{Method: "/test.Service/Test", Authorities: []string{"ADMIN"}},
	}

	md := metadata.New(map[string]string{"authorization": "Bearer token123"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	wantUser := mockGrpcUser{ID: "123", Authorities: []string{"ADMIN"}}
	resp, err := interceptor.InterceptToken(methods)(ctx, nil, info, makeAssertingHandler(t, "token123", wantUser))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestInterceptor_ValidBearerToken_WithExtraSpaces(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error) {
			assert.Equal(t, GrpcBearerTokenType, tokenType)
			// interceptor should TrimSpace
			assert.Equal(t, "token123", token)
			return mockGrpcUser{ID: "123", Authorities: []string{"ADMIN"}}, nil
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)
	methods := []GrpcSecuredMethod{
		{Method: "/test.Service/Test", Authorities: []string{"ADMIN"}},
	}

	md := metadata.New(map[string]string{"authorization": "Bearer   token123   "})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	wantUser := mockGrpcUser{ID: "123", Authorities: []string{"ADMIN"}}
	resp, err := interceptor.InterceptToken(methods)(ctx, nil, info, makeAssertingHandler(t, "token123", wantUser))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestInterceptor_ValidBasicToken(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error) {
			assert.Equal(t, GrpcBasicAuthTokenType, tokenType)
			assert.Equal(t, "dXNlcjpwYXNz", token) // base64("user:pass")
			return mockGrpcUser{ID: "123", Authorities: []string{"ADMIN"}}, nil
		},
	}

	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)
	methods := []GrpcSecuredMethod{
		{Method: "/test.Service/Test", Authorities: []string{"ADMIN"}},
	}

	md := metadata.New(map[string]string{"authorization": "Basic dXNlcjpwYXNz"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	wantUser := mockGrpcUser{ID: "123", Authorities: []string{"ADMIN"}}
	resp, err := interceptor.InterceptToken(methods)(ctx, nil, info, makeAssertingHandler(t, "dXNlcjpwYXNz", wantUser))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestInterceptor_MissingMetadata(t *testing.T) {
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](mockDecoder{})

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: nil}}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(context.Background(), nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptor_MissingToken(t *testing.T) {
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](mockDecoder{})

	md := metadata.New(nil)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: nil}}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptor_InvalidAuthScheme(t *testing.T) {
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](mockDecoder{})

	md := metadata.New(map[string]string{"authorization": "Token abc"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: nil}}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptor_EmptyToken_Bearer(t *testing.T) {
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](mockDecoder{})

	md := metadata.New(map[string]string{"authorization": "Bearer    "})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: nil}}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptor_InvalidToken(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error) {
			return mockGrpcUser{}, errors.New("invalid") // should not be leaked
		},
	}
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)

	md := metadata.New(map[string]string{"authorization": "Bearer badtoken"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: nil}}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptor_AuthoritiesLookupFailure_ReturnsInternal(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error) {
			return mockGrpcUser{ID: "x", Authorities: []string{"USER"}}, nil
		},
		AuthoritiesFunc: func(user mockGrpcUser) ([]string, error) {
			return nil, errors.New("db down")
		},
	}
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)

	md := metadata.New(map[string]string{"authorization": "Bearer token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: []string{"USER"}}}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestInterceptor_InsufficientAuthorities(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(tokenType GrpcAuthTokenType, token string) (mockGrpcUser, error) {
			return mockGrpcUser{ID: "x", Authorities: []string{"USER"}}, nil
		},
	}
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)

	md := metadata.New(map[string]string{"authorization": "Bearer token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	methods := []GrpcSecuredMethod{
		{Method: "/test.Service/Test", Authorities: []string{"ADMIN"}},
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestInterceptor_NoSecuredMethod(t *testing.T) {
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](mockDecoder{})

	info := &grpc.UnaryServerInfo{FullMethod: "/unprotected.Method"}
	resp, err := interceptor.InterceptToken(nil)(context.Background(), nil, info, fakeHandler)

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestGetGrpcUserDetail_Found(t *testing.T) {
	expected := mockGrpcUser{ID: "Alice"}
	ctx := context.WithValue(context.Background(), UserDetailKey, expected)

	actual, ok := ContextUserDetail[mockGrpcUser](ctx)
	assert.True(t, ok)
	assert.Equal(t, expected, actual)
}

func TestGetGrpcUserDetail_NotFound(t *testing.T) {
	ctx := context.Background()

	actual, ok := ContextUserDetail[mockGrpcUser](ctx)
	assert.False(t, ok)
	assert.Equal(t, mockGrpcUser{}, actual)
}

func TestGetGrpcUserDetail_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserDetailKey, "not a user")

	actual, ok := ContextUserDetail[mockGrpcUser](ctx)
	assert.False(t, ok)
	assert.Equal(t, mockGrpcUser{}, actual)
}

func TestGetGrpcAccessToken_Found(t *testing.T) {
	expected := "some-token"
	ctx := context.WithValue(context.Background(), AccessTokenKey, expected)

	actual, ok := ContextAccessToken(ctx)
	assert.True(t, ok)
	assert.Equal(t, expected, actual)
}

func TestGetGrpcAccessToken_NotFound(t *testing.T) {
	ctx := context.Background()

	actual, ok := ContextAccessToken(ctx)
	assert.False(t, ok)
	assert.Equal(t, "", actual)
}
