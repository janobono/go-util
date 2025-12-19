package security

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type grpcContextKey string
type GrpcAuthTokenType string

const (
	grpcBasicAuthPrefix                      = "Basic "
	grpcBearerPrefix                         = "Bearer "
	grpcAccessTokenKey     grpcContextKey    = "accessToken"
	grpcUserDetailKey      grpcContextKey    = "userDetail"
	GrpcBasicAuthTokenType GrpcAuthTokenType = "basic"
	GrpcBearerTokenType    GrpcAuthTokenType = "bearer"
)

type UserDetailDecoder[T any] interface {
	DecodeGrpcUserDetail(ctx context.Context, tokenType GrpcAuthTokenType, token string) (T, error)
	GetGrpcUserAuthorities(ctx context.Context, userDetail T) ([]string, error)
}

type GrpcTokenInterceptor[T any] struct {
	userDetailDecoder UserDetailDecoder[T]
}

func NewGrpcTokenInterceptor[T any](userDetailDecoder UserDetailDecoder[T]) *GrpcTokenInterceptor[T] {
	return &GrpcTokenInterceptor[T]{userDetailDecoder: userDetailDecoder}
}

func (g *GrpcTokenInterceptor[T]) InterceptToken(methods []GrpcSecuredMethod) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		securedMethod := FindGrpcSecuredMethod(methods, info.FullMethod)
		if securedMethod == nil {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		authHeader := md.Get("authorization")
		if len(authHeader) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization")
		}

		raw := authHeader[0]
		var tokenType GrpcAuthTokenType
		var token string

		switch {
		case strings.HasPrefix(raw, grpcBasicAuthPrefix):
			tokenType = GrpcBasicAuthTokenType
			token = strings.TrimSpace(raw[len(grpcBasicAuthPrefix):])
		case strings.HasPrefix(raw, grpcBearerPrefix):
			tokenType = GrpcBearerTokenType
			token = strings.TrimSpace(raw[len(grpcBearerPrefix):])
		default:
			return nil, status.Error(codes.Unauthenticated, "invalid authorization scheme")
		}

		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "empty token")
		}

		userDetail, err := g.userDetailDecoder.DecodeGrpcUserDetail(ctx, tokenType, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		userAuthorities, err := g.userDetailDecoder.GetGrpcUserAuthorities(ctx, userDetail)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to load authorities")
		}

		if len(securedMethod.Authorities) > 0 && !HasAnyAuthority(securedMethod.Authorities, userAuthorities) {
			return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
		}

		ctx = context.WithValue(ctx, grpcAccessTokenKey, token)
		ctx = context.WithValue(ctx, grpcUserDetailKey, userDetail)

		return handler(ctx, req)
	}
}

func GetGrpcAccessToken(ctx context.Context) (string, bool) {
	value := ctx.Value(grpcAccessTokenKey)
	if value == nil {
		return "", false
	}
	typedValue, ok := value.(string)
	return typedValue, ok
}

func GetGrpcUserDetail[T any](ctx context.Context) (T, bool) {
	value := ctx.Value(grpcUserDetailKey)
	if value == nil {
		var zero T
		return zero, false
	}
	typedValue, ok := value.(T)
	return typedValue, ok
}
