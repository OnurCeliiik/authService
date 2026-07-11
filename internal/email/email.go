package email

import "context"

type Sender interface {
	SendPasswordReset(ctx context.Context, to, resetURL string) error
}
