package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Config struct {
	Secret []byte
	TTL    time.Duration
}

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

type Claims struct {
	UserID uuid.UUID
}

func Generate(userID uuid.UUID, cfg Config) (string, time.Time, error) {
	expiresAt := time.Now().Add(cfg.TTL)

	t := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": userID.String(),
			"exp": expiresAt.Unix(),
			"iat": time.Now().Unix(),
		},
	)

	signed, err := t.SignedString(cfg.Secret)
	if err != nil {
		return "", time.Time{}, err
	}

	return signed, expiresAt, nil
}

func ParseAndValidate(cfg Config, token string) (*Claims, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return cfg.Secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return nil, ErrInvalidToken
	}

	return &Claims{UserID: userID}, nil
}

func Validate(cfg Config, token string) (uuid.UUID, error) {
	claims, err := ParseAndValidate(cfg, token)
	if err != nil {
		return uuid.UUID{}, err
	}

	return claims.UserID, nil
}
