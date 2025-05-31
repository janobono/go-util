package common

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

func EnvSafe(key string) (string, error) {
	if env, ok := os.LookupEnv(key); ok && !IsBlank(env) {
		return env, nil
	}
	return "", fmt.Errorf("configuration property %s not set", key)
}

func EnvIntSafe(key string) (int, error) {
	s, err := EnvSafe(key)
	if err != nil {
		return 0, err
	}
	result, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("configuration property %s wrong format: %v", key, err)
	}
	return result, nil
}

func EnvBoolSafe(key string) (bool, error) {
	s, err := EnvSafe(key)
	if err != nil {
		return false, err
	}
	result, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf("configuration property %s wrong format: %v", key, err)
	}
	return result, nil
}

func Env(key string) string {
	s, err := EnvSafe(key)
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func EnvInt(key string) int {
	i, err := EnvIntSafe(key)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func EnvBool(key string) bool {
	b, err := EnvBoolSafe(key)
	if err != nil {
		log.Fatal(err)
	}
	return b
}
