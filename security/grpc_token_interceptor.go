package security

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type GrpcTokenInterceptorService[T any] interface {
	AuthenticationNotRequired(fullMethod string) bool
	AuthorizationNotRequired(fullMethod string) bool
	IsAuthorized(fullMethod string, principal T) bool
	PrincipalService[T]
}

type GrpcTokenInterceptor[T any] struct {
	grpcTokenInterceptorService GrpcTokenInterceptorService[T]
}

func NewGrpcTokenInterceptor[T any](grpcTokenInterceptorService GrpcTokenInterceptorService[T]) *GrpcTokenInterceptor[T] {
	return &GrpcTokenInterceptor[T]{grpcTokenInterceptorService}
}

func (g *GrpcTokenInterceptor[T]) InterceptAuthToken() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if g.grpcTokenInterceptorService.AuthenticationNotRequired(info.FullMethod) {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		authHeader := md.Get("authorization")
		if len(authHeader) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization")
		}
		raw := authHeader[0]

		tokenType, token, err := parseToken(raw)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization scheme")
		}

		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "empty token")
		}

		principal, err := g.grpcTokenInterceptorService.GetPrincipal(tokenType, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		ctx = context.WithValue(ctx, authTokenTypeKey, tokenType)
		ctx = context.WithValue(ctx, authTokenKey, token)
		ctx = context.WithValue(ctx, principalKey, principal)

		if g.grpcTokenInterceptorService.AuthorizationNotRequired(info.FullMethod) {
			return handler(ctx, req)
		}

		if !g.grpcTokenInterceptorService.IsAuthorized(info.FullMethod, principal) {
			return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
		}

		return handler(ctx, req)
	}
}
