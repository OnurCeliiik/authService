package jwt

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Generate builds a signed access token for the user. Reads JWT_SECRET and JWT_TTL from the environment.
func Generate(userID uuid.UUID) (token string, expiresAt time.Time, err error) {
	secret := os.Getenv("JWT_SECRET")
	ttl := 24 * time.Hour
	if s := os.Getenv("JWT_TTL"); s != "" {
		if d, parseErr := time.ParseDuration(s); parseErr == nil {
			ttl = d
		}
	}

	expiresAt = time.Now().Add(ttl)

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID.String(),
		"exp": expiresAt.Unix(),
	})

	signed, err := t.SignedString([]byte(secret))
	return signed, expiresAt, err
}
