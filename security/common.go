package security

type GrpcSecuredMethod struct {
	Method      string
	Authorities []string
}

func HasAnyAuthority(methodAuthorities, userAuthorities []string) bool {
	set := make(map[string]bool)

	for _, item := range methodAuthorities {
		set[item] = true
	}

	for _, item := range userAuthorities {
		if _, found := set[item]; found {
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
