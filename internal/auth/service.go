package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"authService/internal/email"
	"authService/utils/jwt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost            = 12
	passwordResetTokenTTL = 15 * time.Minute
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	FindUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error
	FindValidPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error
	InvalidateUnusedPasswordResetTokensForUser(ctx context.Context, userID uuid.UUID, usedAt time.Time) error
	GetUserTokenVersion(ctx context.Context, userID uuid.UUID) (int, error)
}

type authService struct {
	repo             UserRepository
	jwtCfg           jwt.Config
	exposeResetToken bool
	emailSender      email.Sender
	appBaseURL       string
}

func NewAuthService(
	repo UserRepository,
	jwtCfg jwt.Config,
	exposeResetToken bool,
	emailSender email.Sender,
	appBaseURL string,
) *authService {
	return &authService{
		repo:             repo,
		jwtCfg:           jwtCfg,
		exposeResetToken: exposeResetToken,
		emailSender:      emailSender,
		appBaseURL:       appBaseURL,
	}
}

var _ UserService = (*authService)(nil)

func (s *authService) Signup(ctx context.Context, input *SignupInput) (*SignupResponse, error) {
	existing, err := s.repo.FindUserByEmail(ctx, input.Email)
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
	} else if existing != nil {
		return nil, ErrEmailTaken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcryptCost)
	if err != nil {
		return nil, err
	}

	user := &User{
		Email:        input.Email,
		PasswordHash: string(hash),
		FirstName:    input.Firstname,
		LastName:     input.Lastname,
		TokenVersion: 0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return &SignupResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		CreatedAt: user.CreatedAt,
	}, nil
}

func (s *authService) Login(ctx context.Context, input *LoginInput) (*LoginResponse, error) {
	user, err := s.repo.FindUserByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	token, expiresAt, err := jwt.Generate(user.ID, user.TokenVersion, s.jwtCfg)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(expiresAt).Seconds()),
	}, nil
}

func (s *authService) Me(ctx context.Context, userID uuid.UUID) (*MeResponse, error) {
	user, err := s.repo.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &MeResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		CreatedAt: user.CreatedAt,
	}, nil
}

func (s *authService) ResetPassword(ctx context.Context, input *ResetPasswordInput) (*ResetPasswordResponse, error) {
	tokenHash := hashResetToken(input.Token)
	resetToken, err := s.repo.FindValidPasswordResetToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, ErrResetTokenNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	user, err := s.repo.FindUserByID(ctx, resetToken.UserID)
	if err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcryptCost)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user.PasswordHash = string(hash)
	user.TokenVersion++
	user.UpdatedAt = now

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	if err := s.repo.MarkPasswordResetTokenUsed(ctx, resetToken.ID, now); err != nil {
		return nil, err
	}

	return &ResetPasswordResponse{Success: true}, nil
}

func (s *authService) ForgotPassword(ctx context.Context, input *ForgotPasswordInput) (*ForgotPasswordResponse, error) {
	user, err := s.repo.FindUserByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return &ForgotPasswordResponse{Success: true}, nil
		}
		return nil, err
	}

	now := time.Now()
	if err := s.repo.InvalidateUnusedPasswordResetTokensForUser(ctx, user.ID, now); err != nil {
		return nil, err
	}

	rawToken, err := generateResetToken()
	if err != nil {
		return nil, err
	}

	expiresAt := now.Add(passwordResetTokenTTL)
	resetToken := &PasswordResetToken{
		UserID:    user.ID,
		TokenHash: hashResetToken(rawToken),
		ExpiresAt: expiresAt,
	}
	if err := s.repo.CreatePasswordResetToken(ctx, resetToken); err != nil {
		return nil, err
	}

	resetURL := s.appBaseURL + "/reset-password?token=" + rawToken
	if err := s.emailSender.SendPasswordReset(ctx, user.Email, resetURL); err != nil {
		return nil, err
	}

	resp := &ForgotPasswordResponse{Success: true}
	if s.exposeResetToken {
		resp.ResetToken = rawToken
		resp.ExpiresIn = int64(time.Until(expiresAt).Seconds())
	}

	return resp, nil
}

func (s *authService) ChangePassword(ctx context.Context, userID uuid.UUID, input *ChangePasswordInput) (*ChangePasswordResponse, error) {
	user, err := s.repo.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.CurrentPassword)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if input.CurrentPassword == input.NewPassword {
		return nil, ErrSamePassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcryptCost)
	if err != nil {
		return nil, err
	}

	user.PasswordHash = string(hash)
	user.TokenVersion++
	user.UpdatedAt = time.Now()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	return &ChangePasswordResponse{Success: true}, nil
}

func (s *authService) UpdateMe(ctx context.Context, userID uuid.UUID, input *UpdateMeInput) (*UpdateMeResponse, error) {
	if input.FirstName == "" && input.LastName == "" {
		return nil, ErrNoProfileUpdates
	}

	user, err := s.repo.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if input.FirstName != "" {
		user.FirstName = input.FirstName
	}
	if input.LastName != "" {
		user.LastName = input.LastName
	}
	user.UpdatedAt = time.Now()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	return &UpdateMeResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *authService) LogOut(ctx context.Context, userID uuid.UUID) error {
	user, err := s.repo.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}

	user.TokenVersion++
	user.UpdatedAt = time.Now()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return err
	}

	return nil
}

func generateResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
