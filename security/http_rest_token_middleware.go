package security

import (
	"context"
	"net/http"
)

type HttpRestTokenAuthenticationMiddleware[T any] struct {
	principalService PrincipalService[T]
}

func NewHttpRestTokenAuthenticationMiddleware[T any](principalService PrincipalService[T]) *HttpRestTokenAuthenticationMiddleware[T] {
	return &HttpRestTokenAuthenticationMiddleware[T]{principalService}
}

func (ha *HttpRestTokenAuthenticationMiddleware[T]) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")

		tokenType, token, err := parseToken(raw)
		if err != nil || token == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		principal, err := ha.principalService.GetPrincipal(r.Context(), tokenType, token)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), authTokenTypeKey, tokenType)
		ctx = context.WithValue(ctx, authTokenKey, token)
		ctx = context.WithValue(ctx, principalKey, principal)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type HttpRestTokenAuthorizationService[T any] interface {
	PrincipalService[T]
	IsAuthorized(principal T) bool
}

type HttpRestTokenAuthorizationMiddleware[T any] struct {
	httpRestTokenAuthorizationService HttpRestTokenAuthorizationService[T]
}

func NewHttpRestTokenAuthorizationMiddleware[T any](httpRestTokenAuthorizationService HttpRestTokenAuthorizationService[T]) *HttpRestTokenAuthorizationMiddleware[T] {
	return &HttpRestTokenAuthorizationMiddleware[T]{httpRestTokenAuthorizationService}
}

func (he *HttpRestTokenAuthorizationMiddleware[T]) RequireAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := ContextPrincipal[T](r.Context())
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if !he.httpRestTokenAuthorizationService.IsAuthorized(principal) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
