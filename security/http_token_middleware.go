package security

import (
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	httpBearerPrefix   = "Bearer "
	httpAccessTokenKey = "accessToken"
	httpUserDetailKey  = "userDetail"
)

type HttpHandlers[T any] interface {
	MissingAuthorizationHeader(c *gin.Context)
	Unauthorized(c *gin.Context)
	PermissionDenied(c *gin.Context)
	DecodeUserDetail(c *gin.Context, token string) (T, error)
	GetUserAuthorities(c *gin.Context, userDetail T) ([]string, error)
}

type HttpTokenMiddleware interface {
	HandlerFunc() gin.HandlerFunc
}

type HttpSecurityConfig struct {
	PublicEndpoints map[string]struct{}
	Authorities     map[string][]string
}

type httpTokenMiddleware[T any] struct {
	config       HttpSecurityConfig
	httpHandlers HttpHandlers[T]
}

func NewHttpTokenMiddleware[T any](config HttpSecurityConfig, httpHandlers HttpHandlers[T]) HttpTokenMiddleware {
	return &httpTokenMiddleware[T]{
		config:       config,
		httpHandlers: httpHandlers,
	}
}

func (h *httpTokenMiddleware[T]) HandlerFunc() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		fullPath := ctx.FullPath()
		if fullPath == "" {
			fullPath = ctx.Request.URL.Path // fallback for unmatched routes
		}
		method := ctx.Request.Method

		if isPublic(fullPath, method, h.config.PublicEndpoints) {
			ctx.Next()
			return
		}

		authHeader := ctx.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, httpBearerPrefix) {
			h.httpHandlers.MissingAuthorizationHeader(ctx)
			return
		}
		token := strings.TrimPrefix(authHeader, httpBearerPrefix)

		userDetail, err := h.httpHandlers.DecodeUserDetail(ctx, token)
		if err != nil {
			h.httpHandlers.Unauthorized(ctx)
			return
		}

		allowedRoles, exists := matchAuthorities(fullPath, method, h.config.Authorities)
		if !exists || len(allowedRoles) == 0 {
			ctx.Set(httpAccessTokenKey, token)
			ctx.Set(httpUserDetailKey, userDetail)
			ctx.Next()
			return
		}

		userAuthorities, err := h.httpHandlers.GetUserAuthorities(ctx, userDetail)
		if err != nil {
			h.httpHandlers.PermissionDenied(ctx)
			return
		}

		if !HasAnyAuthority(allowedRoles, userAuthorities) {
			h.httpHandlers.PermissionDenied(ctx)
			return
		}

		ctx.Set(httpAccessTokenKey, token)
		ctx.Set(httpUserDetailKey, userDetail)
		ctx.Next()
	}
}

func GetHttpAccessToken(ctx *gin.Context) (string, bool) {
	value, exists := ctx.Get(httpAccessTokenKey)
	if !exists {
		return "", false
	}
	token, ok := value.(string)
	return token, ok
}

func GetHttpUserDetail[T any](ctx *gin.Context) (T, bool) {
	value, exists := ctx.Get(httpUserDetailKey)
	if !exists {
		var zero T
		return zero, false
	}
	typed, ok := value.(T)
	return typed, ok
}

func isPublic(path, method string, public map[string]struct{}) bool {
	full := method + ":" + path
	if _, ok := public[full]; ok {
		return true
	}
	if _, ok := public["ANY:"+path]; ok {
		return true
	}

	for route := range public {
		if (strings.HasSuffix(route, "/*") && strings.HasPrefix(full, strings.TrimSuffix(route, "*"))) ||
			(strings.HasPrefix(route, "ANY:") && strings.HasSuffix(route, "/*") &&
				strings.HasPrefix("ANY:"+path, strings.TrimSuffix(route, "*"))) {
			return true
		}
	}

	return false
}

func matchAuthorities(path, method string, authorities map[string][]string) ([]string, bool) {
	key := method + ":" + path

	if roles, ok := authorities[key]; ok {
		return roles, true
	}
	if roles, ok := authorities["ANY:"+path]; ok {
		return roles, true
	}

	for routeKey, roles := range authorities {
		if (strings.HasSuffix(routeKey, "/*") && strings.HasPrefix(key, strings.TrimSuffix(routeKey, "*"))) ||
			(strings.HasPrefix(routeKey, "ANY:") && strings.HasSuffix(routeKey, "/*") &&
				strings.HasPrefix("ANY:"+path, strings.TrimSuffix(routeKey, "*"))) {
			return roles, true
		}
	}

	return nil, false
}
