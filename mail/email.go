package mail

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"time"

	"github.com/lnsp/tumtalks/structs"
	"github.com/mailgun/mailgun-go/v4"
)

//go:embed templates/tailwind.min.css
var tailwindStyles []byte

//go:embed templates/*.html
var templates embed.FS

var templateFuncs = template.FuncMap{
	"humandate": func(t time.Time) string {
		return t.Format("02.01.2006 15:04")
	},
}

type Config struct {
	Sender       string
	SenderDomain string
	APIKey       string
	UserDomain   string
}

type Provider struct {
	mg                            mailgun.Mailgun
	sender                        string
	verifyTemplate, loginTemplate *template.Template
	userdomain                    string
}

func NewProvider(cfg *Config) *Provider {
	mg := mailgun.NewMailgun(cfg.SenderDomain, cfg.APIKey)
	mg.SetAPIBase(mailgun.APIBaseEU)

	verifyTemplate := template.Must(template.New("verify.html").Funcs(templateFuncs).ParseFS(templates, "templates/*.html"))
	loginTemplate := template.Must(template.New("login.html").Funcs(templateFuncs).ParseFS(templates, "templates/*.html"))
	return &Provider{
		mg:             mg,
		sender:         cfg.Sender,
		verifyTemplate: verifyTemplate,
		loginTemplate:  loginTemplate,
		userdomain:     cfg.UserDomain,
	}
}

func (mp *Provider) SendLogin(user, code string) error {
	emailData := struct {
		Stylesheet template.CSS
		Code       string
	}{
		Stylesheet: template.CSS(string(tailwindStyles)),
		Code:       code,
	}
	var buf bytes.Buffer
	if err := mp.loginTemplate.Execute(&buf, &emailData); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	message := mp.mg.NewMessage(mp.sender, "Login - IN.TUM Talks", "", user+"@"+mp.userdomain)
	message.SetHtml(buf.String())
	if _, _, err := mp.mg.Send(ctx, message); err != nil {
		return fmt.Errorf("send mail: %w", err)
	}
	return nil
}

func (mp *Provider) SendVerification(user, link string, talk *structs.Talk) error {
	emailData := struct {
		Talk       *structs.Talk
		Stylesheet template.CSS
		Link       string
	}{
		Talk:       talk,
		Stylesheet: template.CSS(string(tailwindStyles)),
		Link:       link,
	}
	var buf bytes.Buffer
	if err := mp.verifyTemplate.Execute(&buf, &emailData); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	message := mp.mg.NewMessage(mp.sender, "Please verify your talk - IN.TUM Talks", "", user+"@"+mp.userdomain)
	message.SetHtml(buf.String())
	if _, _, err := mp.mg.Send(ctx, message); err != nil {
		return fmt.Errorf("send mail: %w", err)
	}
	return nil
}
