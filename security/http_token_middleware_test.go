package security

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
)

type mockHttpUser struct {
	ID    string
	Roles []string
}

type mockHandlers struct{}

func (m *mockHandlers) MissingAuthorizationHeader(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth header"})
}

func (m *mockHandlers) Unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

func (m *mockHandlers) PermissionDenied(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
}

func (m *mockHandlers) DecodeUserDetail(c *gin.Context, token string) (any, error) {
	if token == "valid-token" {
		return mockHttpUser{ID: "1", Roles: []string{"USER"}}, nil
	}
	if token == "admin-token" {
		return mockHttpUser{ID: "2", Roles: []string{"ADMIN"}}, nil
	}
	return nil, errors.New("invalid token")
}

func (m *mockHandlers) GetUserAuthorities(c *gin.Context, userDetail any) ([]string, error) {
	if u, ok := userDetail.(mockHttpUser); ok {
		return u.Roles, nil
	}
	return nil, errors.New("invalid user detail")
}

func setupRouter(config HttpSecurityConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	middleware := NewHttpTokenMiddleware[any](config, &mockHandlers{})
	router.Use(middleware.HandlerFunc())

	router.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "public"})
	})
	router.GET("/secure", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "secure"})
	})
	router.GET("/admin", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin"})
	})

	return router
}
