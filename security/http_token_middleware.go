package security

import (
	"strings"

	"github.com/gin-gonic/gin"
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
	return func(c *gin.Context) {
		fullPath := c.FullPath()
		if fullPath == "" {
			fullPath = c.Request.URL.Path // fallback for unmatched routes
		}
		method := c.Request.Method

		if isPublic(fullPath, method, h.config.PublicEndpoints) {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			h.httpHandlers.MissingAuthorizationHeader(c)
			return
		}
		token := strings.TrimPrefix(authHeader, bearerPrefix)

		userDetail, err := h.httpHandlers.DecodeUserDetail(c, token)
		if err != nil {
			h.httpHandlers.Unauthorized(c)
			return
		}

		allowedRoles, exists := matchAuthorities(fullPath, method, h.config.Authorities)
		if !exists || len(allowedRoles) == 0 {
			c.Set("userDetail", userDetail)
			c.Next()
			return
		}

		userAuthorities, err := h.httpHandlers.GetUserAuthorities(c, userDetail)
		if err != nil {
			h.httpHandlers.PermissionDenied(c)
			return
		}

		if !HasAnyAuthority(allowedRoles, userAuthorities) {
			h.httpHandlers.PermissionDenied(c)
			return
		}

		c.Set("userDetail", userDetail)
		c.Next()
	}
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
