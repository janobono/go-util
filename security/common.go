package security

const bearerPrefix = "Bearer "

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
