package security

import (
	"testing"
)

func TestBasicAuthTokenEncodeDecode_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		password string
	}{
		{"simple", "alice", "secret"},
		{"empty_password", "bob", ""},
		{"empty_user", "", "pw"},
		{"both_empty", "", ""},
		{"password_with_colon", "user", "p:a:ss"},
		{"unicode", "žužu", "pässwörd🙂"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := BasicAuthTokenEncode(tt.user, tt.password)

			gotUser, gotPass, err := BasicAuthTokenDecode(token)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if gotUser != tt.user {
				t.Fatalf("username mismatch: got %q, want %q", gotUser, tt.user)
			}
			if gotPass != tt.password {
				t.Fatalf("password mismatch: got %q, want %q", gotPass, tt.password)
			}
		})
	}
}

func TestBasicAuthTokenDecode_InvalidBase64(t *testing.T) {
	_, _, err := BasicAuthTokenDecode("###not-base64###")
	if err == nil {
		t.Fatalf("expected error for invalid base64, got nil")
	}
}

func TestBasicAuthTokenDecode_MissingColon(t *testing.T) {
	// "userpass" (no colon) base64-encoded
	// This should fail because decoded credentials must contain "user:pass".
	token := "dXNlcnBhc3M="

	_, _, err := BasicAuthTokenDecode(token)
	if err == nil {
		t.Fatalf("expected error for missing colon, got nil")
	}
}

func TestBasicAuthTokenDecode_LeadingColon(t *testing.T) {
	// ":pass"
	token := BasicAuthTokenEncode("", "pass")

	u, p, err := BasicAuthTokenDecode(token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if u != "" || p != "pass" {
		t.Fatalf("got (%q,%q), want (%q,%q)", u, p, "", "pass")
	}
}

func TestBasicAuthTokenDecode_TrailingColon(t *testing.T) {
	// "user:"
	token := BasicAuthTokenEncode("user", "")

	u, p, err := BasicAuthTokenDecode(token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if u != "user" || p != "" {
		t.Fatalf("got (%q,%q), want (%q,%q)", u, p, "user", "")
	}
}
