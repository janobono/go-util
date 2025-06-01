package mail

import (
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/gomail.v2"
)

type JMailData struct {
	From        string
	ReplyTo     string
	Recipients  []string
	Cc          []string
	Subject     string
	Content     *JMailContentData
	Attachments map[string]string // filename -> file path
}

type JMailContentData struct {
	Title string
	Lines []string
	Link  *JMailLinkData
}

type JMailLinkData struct {
	Href string
	Text string
}

type JMailService interface {
	SendEmail(mailData *JMailData) (bool, error)
}

type JMailSender interface {
	DialAndSend(m *gomail.Message) error
}

type JMailContentHtmlFormatter interface {
	Format(content *JMailContentData) (string, error)
}

type mailSender struct {
	smtpHost string
	smtpPort int
	username string
	password string
	useAuth  bool
	useTLS   bool
}

func NewJMailSender(
	smtpHost string,
	smtpPort int,
	username string,
	password string,
	useAuth bool,
	useTLS bool,
) JMailSender {
	return &mailSender{
		smtpHost: smtpHost,
		smtpPort: smtpPort,
		username: username,
		password: password,
		useAuth:  useAuth,
		useTLS:   useTLS,
	}
}

type mailService struct {
	mailSender           JMailSender
	contentHtmlFormatter JMailContentHtmlFormatter
}

func NewJMailService(mailSender JMailSender, contentHtmlFormatter JMailContentHtmlFormatter) JMailService {
	return &mailService{
		mailSender:           mailSender,
		contentHtmlFormatter: contentHtmlFormatter,
	}
}

func (ms *mailSender) DialAndSend(m *gomail.Message) error {
	d := gomail.NewDialer(ms.smtpHost, ms.smtpPort, ms.username, ms.password)
	d.SSL = ms.useTLS
	if !ms.useAuth {
		d.Username = ""
		d.Password = ""
	}

	if err := d.DialAndSend(m); err != nil {
		slog.Error("Email send failed", "error", err)
		return fmt.Errorf("email send failed: %w", err)
	}

	return nil
}

func (ms *mailService) SendEmail(mailData *JMailData) (bool, error) {
	m := gomail.NewMessage()
	m.SetHeader("From", mailData.From)
	m.SetHeader("To", mailData.Recipients...)

	if mailData.ReplyTo != "" {
		m.SetHeader("Reply-To", mailData.ReplyTo)
	}

	if len(mailData.Cc) > 0 {
		m.SetHeader("Cc", mailData.Cc...)
	}

	m.SetHeader("Subject", mailData.Subject)

	body, err := ms.contentHtmlFormatter.Format(mailData.Content)
	if err != nil {
		return false, fmt.Errorf("template formatting failed: %w", err)
	}
	m.SetBody("text/html", body)

	if mailData.Attachments != nil {
		for name, path := range mailData.Attachments {
			m.Attach(path, gomail.Rename(name))
		}
	}

	if err := ms.mailSender.DialAndSend(m); err != nil {
		return false, err
	}

	for _, path := range mailData.Attachments {
		if err := os.Remove(path); err != nil {
			slog.Warn("Failed to delete attachment", "path", path)
		}
	}

	return true, nil
}
