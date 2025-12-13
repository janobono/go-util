package security

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func BasicAuthTokenEncode(user, password string) string {
	credentials := fmt.Sprintf("%s:%s", user, password)
	return base64.StdEncoding.EncodeToString([]byte(credentials))
}

func BasicAuthTokenDecode(token string) (string, string, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", err
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid basic auth token format")
	}

	username := parts[0]
	password := parts[1]

	return username, password, nil
}
