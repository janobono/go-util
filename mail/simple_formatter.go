package mail

import (
	"bytes"
	"fmt"
	"html/template"
)

type simpleHtmlFormatter struct {
	templateText string
}

func NewSimpleHtmlFormatter(templateText string) JMailContentHtmlFormatter {
	if templateText == "" {
		templateText = defaultHtmlTemplate
	}
	return &simpleHtmlFormatter{
		templateText: templateText,
	}
}

const defaultHtmlTemplate = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>{{.Title}}</title>
</head>
<body style="font-family: sans-serif;">
  <h2>{{.Title}}</h2>
  {{range .Lines}}<p>{{.}}</p>{{end}}
  {{if .Link}}<p><a href="{{.Link.Href}}" target="_blank">{{.Link.Text}}</a></p>{{end}}
</body>
</html>
`

func (f *simpleHtmlFormatter) Format(content *JMailContentData) (string, error) {
	tmpl, err := template.New("email").Parse(f.templateText)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, content); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
