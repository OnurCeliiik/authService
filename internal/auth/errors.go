package auth

import "errors"

// custom error types

var (
	ErrEmailTaken         = errors.New("email already registered")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInternal           = errors.New("internal server error")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
)
