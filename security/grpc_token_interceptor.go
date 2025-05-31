package security

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
)

type contextKey struct{}

var userDetailKey = contextKey{}

const bearerPrefix = "Bearer "

type UserDetailDecoder[T any] interface {
	DecodeGrpcUserDetail(token string) (T, error)
	GetGrpcUserAuthorities(userDetail T) []string
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
			if len(authHeader) == 0 || !strings.HasPrefix(authHeader[0], bearerPrefix) {
				return nil, status.Errorf(codes.Unauthenticated, "missing or invalid Bearer token")
			}

			token := authHeader[0][len(bearerPrefix):]
			userDetail, err := g.userDetailDecoder.DecodeGrpcUserDetail(token)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "invalid token")
			}

			userAuthorities := g.userDetailDecoder.GetGrpcUserAuthorities(userDetail)

			if len(securedMethod.Authorities) > 0 && !HasAnyAuthority(securedMethod.Authorities, userAuthorities) {
				return nil, status.Errorf(codes.PermissionDenied, "insufficient permissions")
			}

			ctx = context.WithValue(ctx, userDetailKey, userDetail)
		}

		return handler(ctx, req)
	}
}

func GetGrpcUserDetail[T any](ctx context.Context) (T, bool) {
	value := ctx.Value(userDetailKey)
	if value == nil {
		var zero T
		return zero, false
	}
	typedValue, ok := value.(T)
	return typedValue, ok
}
