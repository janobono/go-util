package security

import (
	"regexp"
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
	PermitAllRequest *regexp.Regexp
	Authorities      map[string][]string
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
		path := c.Request.URL.Path

		if h.config.PermitAllRequest != nil && h.config.PermitAllRequest.MatchString(path) {
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

		allowedRoles, exists := h.config.Authorities[path]
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

func GetHttpUserDetail[T any](c *gin.Context) (T, bool) {
	value, exists := c.Get("userDetail")
	if !exists {
		var zero T
		return zero, false
	}
	typedValue, ok := value.(T)
	return typedValue, ok
}
