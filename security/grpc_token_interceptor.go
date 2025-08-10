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

const (
	grpcBearerPrefix                  = "Bearer "
	grpcAccessTokenKey grpcContextKey = "accessToken"
	grpcUserDetailKey  grpcContextKey = "userDetail"
)

type UserDetailDecoder[T any] interface {
	DecodeGrpcUserDetail(ctx context.Context, token string) (T, error)
	GetGrpcUserAuthorities(ctx context.Context, userDetail T) ([]string, error)
}

type GrpcTokenInterceptor[T any] struct {
	userDetailDecoder UserDetailDecoder[T]
}

func NewGrpcTokenInterceptor[T any](userDetailDecoder UserDetailDecoder[T]) *GrpcTokenInterceptor[T] {
	return &GrpcTokenInterceptor[T]{userDetailDecoder}
}

func (g *GrpcTokenInterceptor[T]) InterceptToken(methods []GrpcSecuredMethod) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		securedMethod := FindGrpcSecuredMethod(methods, info.FullMethod)

		if securedMethod != nil {
			md, ok := metadata.FromIncomingContext(ctx)
			if !ok {
				return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
			}

			authHeader := md.Get("authorization")
			if len(authHeader) == 0 {
				authHeader = md.Get("Authorization")
			}
			if len(authHeader) == 0 || !strings.HasPrefix(authHeader[0], grpcBearerPrefix) {
				return nil, status.Errorf(codes.Unauthenticated, "missing or invalid Bearer token")
			}

			token := authHeader[0][len(grpcBearerPrefix):]
			userDetail, err := g.userDetailDecoder.DecodeGrpcUserDetail(ctx, token)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "%s", err.Error())
			}

			userAuthorities, err := g.userDetailDecoder.GetGrpcUserAuthorities(ctx, userDetail)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "%s", err.Error())
			}

			if len(securedMethod.Authorities) > 0 && !HasAnyAuthority(securedMethod.Authorities, userAuthorities) {
				return nil, status.Errorf(codes.PermissionDenied, "insufficient permissions")
			}

			ctx = context.WithValue(ctx, grpcAccessTokenKey, token)
			ctx = context.WithValue(ctx, grpcUserDetailKey, userDetail)
		}

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
