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
	UserID       uuid.UUID
	TokenVersion int
}

func Generate(userID uuid.UUID, tokenVersion int, cfg Config) (string, time.Time, error) {
	expiresAt := time.Now().Add(cfg.TTL)

	t := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": userID.String(),
			"ver": tokenVersion,
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
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if !t.Valid {
		return nil, ErrInvalidToken
	}

	mapClaims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	sub, err := claimString(mapClaims, "sub")
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, ErrInvalidToken
	}

	ver, err := claimInt(mapClaims, "ver")
	if err != nil {
		return nil, err
	}

	return &Claims{
		UserID:       userID,
		TokenVersion: ver,
	}, nil
}

func claimString(claims jwt.MapClaims, key string) (string, error) {
	raw, ok := claims[key]
	if !ok {
		return "", ErrInvalidToken
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", ErrInvalidToken
	}
	return s, nil
}

func claimInt(claims jwt.MapClaims, key string) (int, error) {
	raw, ok := claims[key]
	if !ok {
		return 0, ErrInvalidToken
	}

	switch v := raw.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	default:
		return 0, ErrInvalidToken
	}
}
