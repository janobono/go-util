package security

import "context"

type contextKey string

const (
	AccessTokenKey contextKey = "accessToken"
	UserDetailKey  contextKey = "userDetail"
)

type GrpcSecuredMethod struct {
	Method      string
	Authorities []string
}

func HasAnyAuthority(required, user []string) bool {
	userSet := make(map[string]struct{}, len(user))
	for _, role := range user {
		userSet[role] = struct{}{}
	}
	for _, requiredRole := range required {
		if _, ok := userSet[requiredRole]; ok {
			return true
		}
	}
	return false
}

func FindGrpcSecuredMethod(methods []GrpcSecuredMethod, methodName string) *GrpcSecuredMethod {
	for _, method := range methods {
		if method.Method == methodName {
			return &method
		}
	}
	return nil
}

func ContextAccessToken(ctx context.Context) (string, bool) {
	value := ctx.Value(AccessTokenKey)
	if value == nil {
		return "", false
	}
	typedValue, ok := value.(string)
	return typedValue, ok
}

func ContextUserDetail[T any](ctx context.Context) (T, bool) {
	value := ctx.Value(UserDetailKey)
	if value == nil {
		var zero T
		return zero, false
	}
	typedValue, ok := value.(T)
	return typedValue, ok
}
