package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"authService/utils/jwt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const ContextKeyUserID = "userID"

type TokenVersionChecker interface {
	GetUserTokenVersion(ctx context.Context, userID uuid.UUID) (int, error)
}

func AuthMiddleware(cfg jwt.Config, versions TokenVersionChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			c.Abort()
			return
		}

		rawToken := strings.TrimSpace(parts[1])
		if rawToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			c.Abort()
			return
		}

		claims, err := jwt.ParseAndValidate(cfg, rawToken)
		if err != nil {
			if errors.Is(err, jwt.ErrExpiredToken) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		currentVersion, err := versions.GetUserTokenVersion(c.Request.Context(), claims.UserID)
		if err != nil || currentVersion != claims.TokenVersion {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Set(ContextKeyUserID, claims.UserID.String())
		c.Next()
	}
}
