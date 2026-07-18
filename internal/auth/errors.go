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
	ErrResetTokenNotFound = errors.New("password reset token not found")
	ErrSamePassword       = errors.New("new password must be different from current password")
	ErrNoProfileUpdates   = errors.New("no profile fields to update")
)
