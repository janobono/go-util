package common

import (
	"os"
	"testing"
)

func TestEnvSafe_Success(t *testing.T) {
	key := "TEST_ENV_STRING"
	val := "value123"
	os.Setenv(key, val)
	defer os.Unsetenv(key)

	got, err := EnvSafe(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != val {
		t.Errorf("Expected %q, got %q", val, got)
	}
}

func TestEnvSafe_Missing(t *testing.T) {
	key := "MISSING_ENV"
	os.Unsetenv(key)

	_, err := EnvSafe(key)
	if err == nil {
		t.Fatal("Expected error for missing env var, got nil")
	}
}

func TestEnvIntSafe_Success(t *testing.T) {
	key := "TEST_ENV_INT"
	os.Setenv(key, "42")
	defer os.Unsetenv(key)

	got, err := EnvIntSafe(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("Expected 42, got %d", got)
	}
}

func TestEnvIntSafe_InvalidFormat(t *testing.T) {
	key := "INVALID_ENV_INT"
	os.Setenv(key, "notanumber")
	defer os.Unsetenv(key)

	_, err := EnvIntSafe(key)
	if err == nil {
		t.Fatal("Expected error for invalid integer format, got nil")
	}
}

func TestEnvBoolSafe_SuccessTrue(t *testing.T) {
	key := "TEST_ENV_BOOL_TRUE"
	os.Setenv(key, "true")
	defer os.Unsetenv(key)

	got, err := EnvBoolSafe(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !got {
		t.Errorf("Expected true, got false")
	}
}

func TestEnvBoolSafe_SuccessFalse(t *testing.T) {
	key := "TEST_ENV_BOOL_FALSE"
	os.Setenv(key, "false")
	defer os.Unsetenv(key)

	got, err := EnvBoolSafe(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got {
		t.Errorf("Expected false, got true")
	}
}

func TestEnvBoolSafe_Invalid(t *testing.T) {
	key := "INVALID_ENV_BOOL"
	os.Setenv(key, "maybe")
	defer os.Unsetenv(key)

	_, err := EnvBoolSafe(key)
	if err == nil {
		t.Fatal("Expected error for invalid boolean format, got nil")
	}
}
