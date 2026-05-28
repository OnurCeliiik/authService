package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"gorm.io/gorm"
)

// UserRepository + postgres implementation

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *userRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) CreateUser(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepository) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User

	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *userRepository) FindUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *userRepository) FindValidPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	var token PasswordResetToken
	err := r.db.WithContext(ctx).
		Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, time.Now()).
		First(&token).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrResetTokenNotFound
	}
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (r *userRepository) MarkPasswordResetTokenUsed(ctx context.Context, tokenID uuid.UUID, usedAt time.Time) error {
	return r.db.WithContext(ctx).
		Model(&PasswordResetToken{}).
		Where("id = ? AND used_at IS NULL", tokenID).
		Update("used_at", usedAt).Error
}
