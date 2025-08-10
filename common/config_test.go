package common

import (
	"os"
	"os/exec"
	"reflect"
	"testing"
)

// --- EnvSafe edge cases ---

func TestEnvSafe_BlankValue(t *testing.T) {
	key := "TEST_ENV_BLANK"
	if err := os.Setenv(key, ""); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	defer os.Unsetenv(key)

	if _, err := EnvSafe(key); err == nil {
		t.Fatal("expected error for blank env var, got nil")
	}
}

// --- Wrappers that log.Fatal on error (tested via subprocess) ---

func TestEnv_Missing_Fatal(t *testing.T) {
	// Subprocess guard
	if os.Getenv("SUBPROC_ENV_MISSING_FATAL") == "1" {
		_ = Env("THIS_ENV_DOES_NOT_EXIST")
		// Env should log.Fatal (os.Exit). If it doesn't, fail here.
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestEnv_Missing_Fatal")
	cmd.Env = append(os.Environ(), "SUBPROC_ENV_MISSING_FATAL=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected subprocess to exit with non-zero due to log.Fatal, got nil error")
	}
}

func TestEnvInt_Invalid_Fatal(t *testing.T) {
	if os.Getenv("SUBPROC_ENVINT_INVALID_FATAL") == "1" {
		key := "TEST_ENV_INT_INVALID_FATAL"
		os.Setenv(key, "not-an-int")
		defer os.Unsetenv(key)
		_ = EnvInt(key)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestEnvInt_Invalid_Fatal")
	cmd.Env = append(os.Environ(), "SUBPROC_ENVINT_INVALID_FATAL=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected subprocess to exit with non-zero due to log.Fatal, got nil error")
	}
}

func TestEnvBool_Invalid_Fatal(t *testing.T) {
	if os.Getenv("SUBPROC_ENVBOOL_INVALID_FATAL") == "1" {
		key := "TEST_ENV_BOOL_INVALID_FATAL"
		os.Setenv(key, "maybe")
		defer os.Unsetenv(key)
		_ = EnvBool(key)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestEnvBool_Invalid_Fatal")
	cmd.Env = append(os.Environ(), "SUBPROC_ENVBOOL_INVALID_FATAL=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected subprocess to exit with non-zero due to log.Fatal, got nil error")
	}
}

// --- Wrappers happy paths ---

func TestEnv_Success(t *testing.T) {
	key, val := "TEST_ENV_STRING_WRAPPER", "ok"
	os.Setenv(key, val)
	defer os.Unsetenv(key)

	got := Env(key)
	if got != val {
		t.Fatalf("Env: expected %q, got %q", val, got)
	}
}

func TestEnvInt_Success(t *testing.T) {
	key := "TEST_ENV_INT_WRAPPER"
	os.Setenv(key, "7")
	defer os.Unsetenv(key)

	got := EnvInt(key)
	if got != 7 {
		t.Fatalf("EnvInt: expected 7, got %d", got)
	}
}

func TestEnvBool_SuccessTrue(t *testing.T) {
	key := "TEST_ENV_BOOL_WRAPPER_TRUE"
	os.Setenv(key, "true")
	defer os.Unsetenv(key)

	if got := EnvBool(key); !got {
		t.Fatalf("EnvBool: expected true, got false")
	}
}

func TestEnvBool_SuccessFalse(t *testing.T) {
	key := "TEST_ENV_BOOL_WRAPPER_FALSE"
	os.Setenv(key, "false")
	defer os.Unsetenv(key)

	if got := EnvBool(key); got {
		t.Fatalf("EnvBool: expected false, got true")
	}
}

// --- EnvSlice ---

func TestEnvSlice_Success(t *testing.T) {
	key := "TEST_ENV_SLICE"
	os.Setenv(key, "a,b,c")
	defer os.Unsetenv(key)

	got := EnvSlice(key)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EnvSlice: expected %#v, got %#v", want, got)
	}
}

// --- EnvMap ---

func TestEnvMap_SuccessTrimAndIgnoreEmpty(t *testing.T) {
	key := "TEST_ENV_MAP"
	// Includes spaces and empty segments to ensure trimming and skipping work.
	os.Setenv(key, " a=1 , b = 2 ,, c= 3 ,  ,d=4 ")
	defer os.Unsetenv(key)

	got := EnvMap(key)
	want := map[string]string{
		"a": "1",
		"b": "2",
		"c": "3",
		"d": "4",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EnvMap: expected %#v, got %#v", want, got)
	}
}

func TestEnvMap_InvalidEntry_Fatal(t *testing.T) {
	if os.Getenv("SUBPROC_ENVMAP_INVALID_FATAL") == "1" {
		key := "TEST_ENV_MAP_INVALID"
		os.Setenv(key, "valid=1,invalidpair,another=2")
		defer os.Unsetenv(key)
		_ = EnvMap(key) // should log.Fatalf (os.Exit)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestEnvMap_InvalidEntry_Fatal")
	cmd.Env = append(os.Environ(), "SUBPROC_ENVMAP_INVALID_FATAL=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected subprocess to exit with non-zero due to log.Fatalf, got nil error")
	}
}
