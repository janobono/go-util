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
		"GET:/secure":        {"USER"},
		"GET:/admin":         {"ADMIN"},
		"GET:/wildsecure/*":  {"USER"},
		"ANY:/common/secure": {"USER"},
		"GET:/users/:id":     {"USER"}, // path param route
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
		{"Public endpoint", "GET", "/public", "", http.StatusOK, `{"message":"public"}`},
		{"Any method public endpoint", "POST", "/anypublic", "", http.StatusOK, `{"message":"anypublic"}`},
		{"Wildcard public endpoint", "GET", "/wildcard/something", "", http.StatusOK, `{"message":"wildcard"}`},
		{"ANY wildcard public endpoint", "GET", "/anywildcard/match", "", http.StatusOK, `{"message":"anywildcard"}`},
		{"Secure with valid USER token", "GET", "/secure", "Bearer valid-token", http.StatusOK, `{"message":"secure"}`},
		{"Secure with missing token", "GET", "/secure", "", http.StatusUnauthorized, `{"error":"missing auth header"}`},
		{"Secure with invalid token", "GET", "/secure", "Bearer bad-token", http.StatusUnauthorized, `{"error":"unauthorized"}`},
		{"Admin with valid admin token", "GET", "/admin", "Bearer admin-token", http.StatusOK, `{"message":"admin"}`},
		{"Admin with user token - forbidden", "GET", "/admin", "Bearer valid-token", http.StatusForbidden, `{"error":"forbidden"}`},
		{"Wildcard authority match with USER token", "GET", "/wildsecure/resource", "Bearer valid-token", http.StatusOK, `{"message":"wildsecure"}`},
		{"ANY method authority match - POST", "POST", "/common/secure", "Bearer valid-token", http.StatusOK, `{"message":"common"}`},

		// New tests for path param
		{"Path param - valid user token", "GET", "/users/123", "Bearer valid-token", http.StatusOK, `"message":"user with id"`},
		{"Path param - missing token", "GET", "/users/123", "", http.StatusUnauthorized, `"error":"missing auth header"`},
		{"Path param - invalid token", "GET", "/users/123", "Bearer bad-token", http.StatusUnauthorized, `"error":"unauthorized"`},
		{"Path param - insufficient role", "GET", "/users/123", "Bearer admin-token", http.StatusForbidden, `"error":"forbidden"`},
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
	router.GET("/wildsecure/*any", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "wildsecure"})
	})
	router.POST("/common/secure", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "common"})
	})
	router.GET("/users/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "user with id", "id": c.Param("id")})
	})

	return router
}
