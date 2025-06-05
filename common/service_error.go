package common

import (
	"errors"
	"fmt"
)

type ServiceError struct {
	Code    string
	Message string
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func IsCode(err error, code string) bool {
	var se *ServiceError
	if errors.As(err, &se) {
		return se.Code == code
	}
	return false
}

func NewServiceError(code string, message string) *ServiceError {
	return &ServiceError{Code: code, Message: message}
}
