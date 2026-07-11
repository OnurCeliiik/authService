package auth

import (
	"authService/internal/middleware"
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Gin HTTP adapter layer

type UserService interface {
	Signup(ctx context.Context, input *SignupInput) (*SignupResponse, error)
	Login(ctx context.Context, input *LoginInput) (*LoginResponse, error)
	ResetPassword(ctx context.Context, input *ResetPasswordInput) (*ResetPasswordResponse, error)
	ForgotPassword(ctx context.Context, input *ForgotPasswordInput) (*ForgotPasswordResponse, error)
	Me(ctx context.Context, userID uuid.UUID) (*MeResponse, error)
}

type AuthHandler struct {
	service UserService
}

func NewAuthHandler(service UserService) *AuthHandler {
	return &AuthHandler{
		service: service,
	}
}

func (h *AuthHandler) Signup(c *gin.Context) {

	var req SignupRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Password != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passwords do not match"})
		return
	}

	resp, err := h.service.Signup(c.Request.Context(), &SignupInput{
		Email:     req.Email,
		Password:  req.Password,
		Firstname: req.FirstName,
		Lastname:  req.LastName,
	})

	if err != nil {
		switch {
		case errors.Is(err, ErrEmailTaken):
			log.Println("email already taken: ", err)
			c.JSON(http.StatusConflict, gin.H{"error": "email already taken"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	loginInput := &LoginInput{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := h.service.Login(c.Request.Context(), loginInput)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			log.Println("invalid credentials: ", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) Me(c *gin.Context) {
	rawUserID, exists := c.Get(middleware.ContextKeyUserID)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	userIDStr, ok := rawUserID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	resp, err := h.service.Me(c.Request.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.NewPassword != req.ConfirmNewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passwords do not match"})
		return
	}

	resp, err := h.service.ResetPassword(c.Request.Context(), &ResetPasswordInput{
		NewPassword: req.NewPassword,
		Token:       req.Token,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidToken):
			log.Println("invalid reset token: ", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.service.ForgotPassword(c.Request.Context(), &ForgotPasswordInput{
		Email: req.Email,
	})
	if err != nil {
		log.Println("internal server error: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, resp)
}
