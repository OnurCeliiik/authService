package auth

import (
	"context"
	"errors"
	"time"

	"authService/utils/jwt"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// Business logic and validation

type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	FindUserByEmail(ctx context.Context, email string) (*User, error)
}

type authService struct {
	repo UserRepository
}

func NewAuthService(repo UserRepository) *authService {
	return &authService{repo: repo}
}

var _ UserService = (*authService)(nil)

func (s *authService) Signup(ctx context.Context, input *SignupInput) (*SignupResponse, error) {

	// check if email is already taken. If existing returns not nil, that means email is already taken.
	existing, err := s.repo.FindUserByEmail(ctx, input.Email)
	if err == nil && existing != nil {
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

	token, expiresAt, err := jwt.Generate(user.ID)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(expiresAt).Seconds()),
	}, nil
}
