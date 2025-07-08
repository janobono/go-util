package common

import (
	"errors"
	"fmt"
)

type ServiceError struct {
	Status  int
	Code    string
	Message string
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("(%d)[%s] %s", e.Status, e.Code, e.Message)
}

func IsCode(err error, code string) bool {
	var se *ServiceError
	if errors.As(err, &se) {
		return se.Code == code
	}
	return false
}

func NewServiceError(status int, code string, message string) *ServiceError {
	return &ServiceError{Status: status, Code: code, Message: message}
}
