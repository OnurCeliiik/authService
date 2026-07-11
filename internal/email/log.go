package email

import (
	"context"
	"log"
)

type LogSender struct{}

func NewLogSender() *LogSender {
	return &LogSender{}
}

func (s *LogSender) SendPasswordReset(ctx context.Context, to, resetURL string) error {
	log.Printf("password reset email to=%s, url=%s", to, resetURL)
	return nil
}
