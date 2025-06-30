package common

import (
	"regexp"
	"strings"
)

func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func NotBlank(value string) bool {
	return !IsBlank(value)
}

func SplitWithoutBlank(value, separator string) []string {
	if IsBlank(value) {
		return []string{}
	}

	return FilterBlank(strings.Split(value, separator))
}

func FilterBlank(values []string) []string {
	result := make([]string, 0, len(values))

	for _, part := range values {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

func Deduplicate(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))

	for _, v := range values {
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}

	return result
}

func IsValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}
