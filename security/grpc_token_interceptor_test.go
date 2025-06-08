package security

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGrpcUser struct {
	ID          string
	Authorities []string
}

type mockDecoder struct {
	DecodeFunc func(string) (mockGrpcUser, error)
}

func (m mockDecoder) DecodeGrpcUserDetail(ctx context.Context, token string) (mockGrpcUser, error) {
	return m.DecodeFunc(token)
}

func (m mockDecoder) GetGrpcUserAuthorities(ctx context.Context, user mockGrpcUser) ([]string, error) {
	return user.Authorities, nil
}

func fakeHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "ok", nil
}

func TestInterceptor_ValidToken(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(token string) (mockGrpcUser, error) {
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

	resp, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestInterceptor_MissingMetadata(t *testing.T) {
	decoder := mockDecoder{}
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: nil}}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}
	_, err := interceptor.InterceptToken(methods)(context.Background(), nil, info, fakeHandler)

	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptor_MissingToken(t *testing.T) {
	decoder := mockDecoder{}
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)

	md := metadata.New(nil)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	methods := []GrpcSecuredMethod{{Method: "/test.Service/Test", Authorities: nil}}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}

	_, err := interceptor.InterceptToken(methods)(ctx, nil, info, fakeHandler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptor_InvalidToken(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(token string) (mockGrpcUser, error) {
			return mockGrpcUser{}, errors.New("invalid")
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

func TestInterceptor_InsufficientAuthorities(t *testing.T) {
	decoder := mockDecoder{
		DecodeFunc: func(token string) (mockGrpcUser, error) {
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
	decoder := mockDecoder{}
	interceptor := NewGrpcTokenInterceptor[mockGrpcUser](decoder)

	info := &grpc.UnaryServerInfo{FullMethod: "/unprotected.Method"}
	resp, err := interceptor.InterceptToken(nil)(context.Background(), nil, info, fakeHandler)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestGetGrpcUserDetail_Found(t *testing.T) {
	expected := mockGrpcUser{ID: "Alice"}

	ctx := context.WithValue(context.Background(), userDetailKey, expected)

	actual, ok := GetGrpcUserDetail[mockGrpcUser](ctx)
	assert.True(t, ok)
	assert.Equal(t, expected, actual)
}

func TestGetGrpcUserDetail_NotFound(t *testing.T) {
	ctx := context.Background()

	actual, ok := GetGrpcUserDetail[mockGrpcUser](ctx)
	assert.False(t, ok)
	assert.Equal(t, mockGrpcUser{}, actual)
}

func TestGetGrpcUserDetail_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), userDetailKey, "not a user")

	actual, ok := GetGrpcUserDetail[mockGrpcUser](ctx)
	assert.False(t, ok)
	assert.Equal(t, mockGrpcUser{}, actual)
}
