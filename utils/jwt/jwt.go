package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Config struct {
	Secret []byte
	TTL    time.Duration
}

// Generate builds a signed access token for the user. Reads JWT_SECRET and JWT_TTL from the environment.
func Generate(userID uuid.UUID, cfg Config) (token string, expiresAt time.Time, err error) {
	expiresAt = time.Now().Add(cfg.TTL)

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID.String(),
		"exp": expiresAt.Unix(),
	})

	signed, err := t.SignedString(cfg.Secret)
	return signed, expiresAt, err
}

func Validate(cfg Config, token string) (uuid.UUID, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return cfg.Secret, nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, fmt.Errorf("invalid token claims")
	}

	sub, ok := claims["sub"].(string)

	if !ok {
		return uuid.Nil, fmt.Errorf("invalid token claims")
	}

	userID, err := uuid.Parse(sub)

	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID: %w", err)
	}

	return userID, nil
}

func Parse(cfg Config, token string) (uuid.UUID, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return cfg.Secret, nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)

	if !ok {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	sub, ok := claims["sub"].(string)

	if !ok {
		return uuid.Nil, fmt.Errorf("invalid token claims")
	}

	userID, err := uuid.Parse(sub)

	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID: %w", err)
	}

	return userID, nil
}
