package mail

import (
	"errors"
	"testing"

	"gopkg.in/gomail.v2"
)

// Mock formatter
type mockFormatter struct {
	content string
	err     error
}

func (m *mockFormatter) Format(content *JMailContentData) (string, error) {
	return m.content, m.err
}

// Mock sender
type mockSender struct {
	fail bool
}

func (s *mockSender) DialAndSend(m *gomail.Message) error {
	if s.fail {
		return errors.New("SMTP error")
	}
	return nil
}

func TestSendEmail_Success(t *testing.T) {
	formatter := &mockFormatter{
		content: "<p>Hello</p>",
	}
	sender := &mockSender{}

	service := NewJMailService(sender, formatter)

	success, err := service.SendEmail(&JMailData{
		From:       "me@example.com",
		Recipients: []string{"you@example.com"},
		Subject:    "Test",
		Content:    &JMailContentData{Title: "Hi"},
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !success {
		t.Error("Expected success to be true")
	}
}

func TestSendEmail_FormatterFails(t *testing.T) {
	formatter := &mockFormatter{
		err: errors.New("formatting failed"),
	}
	sender := &mockSender{}

	service := NewJMailService(sender, formatter)

	success, err := service.SendEmail(&JMailData{
		From:       "me@example.com",
		Recipients: []string{"you@example.com"},
		Subject:    "Test",
		Content:    &JMailContentData{Title: "Hi"},
	})

	if err == nil {
		t.Error("Expected error, got nil")
	}
	if success {
		t.Error("Expected success to be false")
	}
}

func TestSendEmail_SmtpFails(t *testing.T) {
	formatter := &mockFormatter{
		content: "<p>Hello</p>",
	}
	sender := &mockSender{fail: true}

	service := NewJMailService(sender, formatter)

	success, err := service.SendEmail(&JMailData{
		From:       "me@example.com",
		Recipients: []string{"you@example.com"},
		Subject:    "Test",
		Content:    &JMailContentData{Title: "Hi"},
	})

	if err == nil {
		t.Error("Expected error, got nil")
	}
	if success {
		t.Error("Expected success to be false")
	}
}
