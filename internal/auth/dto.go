package auth

import (
	"time"

	"github.com/google/uuid"
)

// request and response JSON structs

type SignupRequest struct {
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=6"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
	FirstName       string `json:"first_name" binding:"required"`
	LastName        string `json:"last_name" binding:"required"`
}

type SignupInput struct {
	Email     string
	Password  string
	Firstname string
	Lastname  string
}

type SignupResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginInput struct {
	Email    string
	Password string
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type ResetPasswordRequest struct {
	NewPassword        string `json:"new_password" binding:"required,min=6"`
	ConfirmNewPassword string `json:"confirm_new_password" binding:"required"`
	Token              string `json:"token" binding:"required"`
}

type ResetPasswordInput struct {
	NewPassword string
	Token       string
}

type ResetPasswordResponse struct {
	Success bool `json:"success"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ForgotPasswordInput struct {
	Email string
}

type ForgotPasswordResponse struct {
	Success    bool   `json:"success"`
	ResetToken string `json:"reset_token,omitempty"`
	ExpiresIn  int64  `json:"expires_in,omitempty"`
}

type MeResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
}
