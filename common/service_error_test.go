package common

import (
	"errors"
	"fmt"
	"testing"
)

func TestNewServiceError(t *testing.T) {
	err := NewServiceError(0, "TEST_CODE", "Something went wrong")

	if err.Code != "TEST_CODE" {
		t.Errorf("Expected code 'TEST_CODE', got '%s'", err.Code)
	}

	if err.Message != "Something went wrong" {
		t.Errorf("Expected message 'Something went wrong', got '%s'", err.Message)
	}

	expectedErrorString := "(0)[TEST_CODE] Something went wrong"
	if err.Error() != expectedErrorString {
		t.Errorf("Expected Error() to return '%s', got '%s'", expectedErrorString, err.Error())
	}
}

func TestIsCode_Match(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", NewServiceError(0, "MATCH_CODE", "match test"))

	if !IsCode(err, "MATCH_CODE") {
		t.Errorf("Expected IsCode to return true for matching code")
	}
}

func TestIsCode_NoMatch(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", NewServiceError(0, "DIFFERENT_CODE", "no match"))

	if IsCode(err, "NON_EXISTENT_CODE") {
		t.Errorf("Expected IsCode to return false for non-matching code")
	}
}

func TestIsCode_NotServiceError(t *testing.T) {
	err := errors.New("some standard error")

	if IsCode(err, "ANY_CODE") {
		t.Errorf("Expected IsCode to return false for non-ServiceError")
	}
}
