package security

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
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

func TestHttpTokenMiddleware(t *testing.T) {
	publicEndpoints := map[string]struct{}{
		"GET:/public":        {},
		"POST:/anypublic":    {},
		"GET:/wildcard/*":    {},
		"ANY:/anywildcard/*": {},
	}

	authorities := map[string][]string{
		"GET:/secure": {"USER"},
		"GET:/admin":  {"ADMIN"},
	}

	config := HttpSecurityConfig{
		PublicEndpoints: publicEndpoints,
		Authorities:     authorities,
	}

	router := setupRouter(config)

	tests := []struct {
		name           string
		method         string
		url            string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Public endpoint",
			method:         "GET",
			url:            "/public",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"public"}`,
		},
		{
			name:           "Any method public endpoint",
			method:         "POST",
			url:            "/anypublic",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"anypublic"}`,
		},
		{
			name:           "Wildcard public endpoint",
			method:         "GET",
			url:            "/wildcard/something",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"wildcard"}`,
		},
		{
			name:           "ANY wildcard public endpoint",
			method:         "GET",
			url:            "/anywildcard/match",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"anywildcard"}`,
		},
		{
			name:           "Secure with valid USER token",
			method:         "GET",
			url:            "/secure",
			authHeader:     "Bearer valid-token",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"secure"}`,
		},
		{
			name:           "Secure with missing token",
			method:         "GET",
			url:            "/secure",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"missing auth header"}`,
		},
		{
			name:           "Secure with invalid token",
			method:         "GET",
			url:            "/secure",
			authHeader:     "Bearer bad-token",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"unauthorized"}`,
		},
		{
			name:           "Admin with valid admin token",
			method:         "GET",
			url:            "/admin",
			authHeader:     "Bearer admin-token",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"admin"}`,
		},
		{
			name:           "Admin with user token - forbidden",
			method:         "GET",
			url:            "/admin",
			authHeader:     "Bearer valid-token",
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"error":"forbidden"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, tt.url, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, req)

			assert.Equal(t, tt.expectedStatus, resp.Code)
			assert.Contains(t, strings.TrimSpace(resp.Body.String()), tt.expectedBody)
		})
	}
}

func setupRouter(config HttpSecurityConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	middleware := NewHttpTokenMiddleware[any](config, &mockHandlers{})
	router.Use(middleware.HandlerFunc())

	router.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "public"})
	})
	router.POST("/anypublic", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "anypublic"})
	})
	router.GET("/wildcard/*any", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "wildcard"})
	})
	router.GET("/anywildcard/*any", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "anywildcard"})
	})
	router.GET("/secure", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "secure"})
	})
	router.GET("/admin", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin"})
	})
	return router
}
