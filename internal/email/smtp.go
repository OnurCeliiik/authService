package email

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPSender struct {
	host string
	port string
	from string
}

func NewSMTPSender(host, port, from string) *SMTPSender {
	return &SMTPSender{
		host: host,
		port: port,
		from: from,
	}
}

func (s *SMTPSender) SendPasswordReset(ctx context.Context, to, resetURL string) error {
	addr := fmt.Sprintf("%s:%s", s.host, s.port)

	subject := "Reset your password"
	body := fmt.Sprintf("Click this link to reset your password:\n\n%s\n", resetURL)

	msg := []byte(
		"From: " + s.from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
			"\r\n" +
			body + "\r\n",
	)

	// nil auth = no username/password
	return smtp.SendMail(addr, nil, s.from, []string{to}, msg)
}
