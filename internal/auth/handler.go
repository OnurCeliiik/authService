package auth

import (
	"authService/internal/middleware"
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// Gin HTTP adapter layer

type UserService interface {
	Signup(ctx context.Context, input *SignupInput) (*SignupResponse, error)
	Login(ctx context.Context, input *LoginInput) (*LoginResponse, error)
	Refresh(ctx context.Context, input *RefreshInput) (*LoginResponse, error)
	ResetPassword(ctx context.Context, input *ResetPasswordInput) (*ResetPasswordResponse, error)
	ForgotPassword(ctx context.Context, input *ForgotPasswordInput) (*ForgotPasswordResponse, error)
	Me(ctx context.Context, userID uuid.UUID) (*MeResponse, error)
	ChangePassword(ctx context.Context, userID uuid.UUID, input *ChangePasswordInput) (*ChangePasswordResponse, error)
	UpdateMe(ctx context.Context, userID uuid.UUID, input *UpdateMeInput) (*UpdateMeResponse, error)
	LogOut(ctx context.Context, userID uuid.UUID) error
	LoginWithGoogle(ctx context.Context, profile *GoogleProfile) (*LoginResponse, error)
}

type AuthHandler struct {
	service   UserService
	googlecfg *oauth2.Config
}

func NewAuthHandler(service UserService, googlecfg *oauth2.Config) *AuthHandler {
	return &AuthHandler{
		service:   service,
		googlecfg: googlecfg,
	}
}

func userIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	rawUserID, exists := c.Get(middleware.ContextKeyUserID)
	if !exists {
		return uuid.Nil, false
	}

	userIDStr, ok := rawUserID.(string)
	if !ok {
		return uuid.Nil, false
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, false
	}

	return userID, true
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
		case errors.Is(err, ErrNoLocalPassword):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "use google login for this account"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.service.Refresh(c.Request.Context(), &RefreshInput{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidToken):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := userIDFromContext(c)
	if !ok {
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

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, ok := userIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.NewPassword != req.ConfirmNewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passwords do not match"})
		return
	}

	resp, err := h.service.ChangePassword(c.Request.Context(), userID, &ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		case errors.Is(err, ErrNoLocalPassword):
			c.JSON(http.StatusBadRequest, gin.H{"error": "account has no local password; use google login"})
		case errors.Is(err, ErrSamePassword):
			c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be different from current password"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) UpdateMe(c *gin.Context) {
	userID, ok := userIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	var req UpdateMeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.service.UpdateMe(c.Request.Context(), userID, &UpdateMeInput{
		UserID:    userID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNoProfileUpdates):
			c.JSON(http.StatusBadRequest, gin.H{"error": "provide first_name and/or last_name"})
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

func (h *AuthHandler) LogOut(c *gin.Context) {
	userID, ok := userIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	if err := h.service.LogOut(c.Request.Context(), userID); err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		default:
			log.Println("internal server error: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *AuthHandler) GoogleOAuth(c *gin.Context) {
	if h.googlecfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "google oauth is not configured"})
		return
	}

	state, err := generateOpaqueToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("oauth_state", state, 600, "/", "", false, true)
	url := h.googlecfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	if h.googlecfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "google oauth is not configured"})
		return
	}

	if errMsg := c.Query("error"); errMsg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	state := c.Query("state")
	cookieState, err := c.Cookie("oauth_state")
	if err != nil || state == "" || state != cookieState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid oauth state"})
		return
	}
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	token, err := h.googlecfg.Exchange(c.Request.Context(), code)
	if err != nil {
		log.Println("google token exchange failed: ", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to exchange google code"})
		return
	}

	profile, err := FetchGoogleProfile(c.Request.Context(), token.AccessToken)
	if err != nil {
		log.Println("google userinfo failed: ", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch google profile"})
		return
	}

	resp, err := h.service.LoginWithGoogle(c.Request.Context(), profile)
	if err != nil {
		log.Println("google login failed: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, resp)
}
