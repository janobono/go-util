package mail

import (
	"strings"
	"testing"
)

func TestFormat_UsesDefaultTemplate(t *testing.T) {
	formatter := NewSimpleHtmlFormatter("")

	content := &JMailContentData{
		Title: "Welcome!",
		Lines: []string{"Line 1", "Line 2"},
		Link: &JMailLinkData{
			Href: "https://example.com",
			Text: "Click here",
		},
	}

	result, err := formatter.Format(content)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !strings.Contains(result, "<h2>Welcome!</h2>") {
		t.Errorf("Expected title in HTML, got: %s", result)
	}

	if !strings.Contains(result, "<p>Line 1</p>") || !strings.Contains(result, "<p>Line 2</p>") {
		t.Errorf("Expected lines in HTML, got: %s", result)
	}

	if !strings.Contains(result, `<a href="https://example.com" target="_blank">Click here</a>`) {
		t.Errorf("Expected link in HTML, got: %s", result)
	}
}

func TestFormat_UsesCustomTemplate(t *testing.T) {
	customTemplate := `
		<html><body><h1>{{.Title}}</h1>{{range .Lines}}<li>{{.}}</li>{{end}}</body></html>
	`
	formatter := NewSimpleHtmlFormatter(customTemplate)

	content := &JMailContentData{
		Title: "News",
		Lines: []string{"Item A", "Item B"},
	}

	result, err := formatter.Format(content)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !strings.Contains(result, "<h1>News</h1>") {
		t.Errorf("Expected custom title in HTML, got: %s", result)
	}

	if !strings.Contains(result, "<li>Item A</li>") || !strings.Contains(result, "<li>Item B</li>") {
		t.Errorf("Expected list items in HTML, got: %s", result)
	}
}

func TestFormat_InvalidTemplate_ReturnsError(t *testing.T) {
	badTemplate := `<html><body>{{.Title</body></html>`
	formatter := NewSimpleHtmlFormatter(badTemplate)

	content := &JMailContentData{
		Title: "Broken",
	}

	_, err := formatter.Format(content)
	if err == nil {
		t.Error("Expected error due to bad template, got nil")
	}
}
