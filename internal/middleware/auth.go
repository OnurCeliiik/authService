package middleware

import (
	"authService/utils/jwt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const ContextKeyUserID = "userID"

func AuthMiddleware(cfg jwt.Config) gin.HandlerFunc {
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
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Set(ContextKeyUserID, claims.UserID.String())
		c.Next()
	}
}
