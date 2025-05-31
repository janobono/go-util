package common

import (
	"golang.org/x/text/unicode/norm"
	"strings"
)

func ToDf(text string) string {
	if IsBlank(text) {
		return ""
	}

	var result strings.Builder
	for _, r := range text {
		normalized := norm.NFD.String(string(r))
		if len(normalized) > 1 {
			result.WriteRune(rune(normalized[0]))
		} else {
			result.WriteRune(r)
		}
	}

	return strings.TrimSpace(result.String())
}

func ToScDf(text string) string {
	if IsBlank(text) {
		return ""
	}
	return strings.ToLower(ToDf(text))
}
