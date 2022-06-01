package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"time"

	"github.com/mailgun/mailgun-go/v4"
)

type MailConfig struct {
	Sender       string
	SenderDomain string
	APIKey       string
	UserDomain   string
}

type MailProvider struct {
	mg         mailgun.Mailgun
	sender     string
	template   *template.Template
	userdomain string
}

func NewMailProvider(cfg *MailConfig, templates fs.FS) *MailProvider {
	mg := mailgun.NewMailgun(cfg.SenderDomain, cfg.APIKey)
	mg.SetAPIBase(mailgun.APIBaseEU)

	return &MailProvider{
		mg:         mg,
		sender:     cfg.Sender,
		template:   template.Must(template.New("verify.html").Funcs(templateFuncs).ParseFS(templates, "email/*.html")),
		userdomain: cfg.UserDomain,
	}
}

func (mp *MailProvider) SendVerification(user, link string, talk *Talk) error {
	emailData := struct {
		Talk       *Talk
		Stylesheet template.CSS
		Link       string
	}{
		Talk:       talk,
		Stylesheet: template.CSS(string(tailwindStyles)),
		Link:       link,
	}
	var buf bytes.Buffer
	if err := mp.template.Execute(&buf, &emailData); err != nil {
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
