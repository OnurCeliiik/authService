package routes

import (
	"authService/internal/auth"
	"authService/internal/health"
	"authService/internal/middleware"
	"authService/utils/jwt"
	"time"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(
	router *gin.Engine,
	healthHandler *health.Handler,
	authHandler *auth.AuthHandler,
	jwtCfg jwt.Config,
) {
	router.GET("/health", healthHandler.Health)

	v1 := router.Group("/api/v1")
	{
		authRateLimit := middleware.RateLimitByIP(20, time.Minute)
		v1.POST("/signup", authRateLimit, authHandler.Signup)
		v1.POST("/login", authRateLimit, authHandler.Login)

		protected := v1.Group("")
		protected.Use(middleware.AuthMiddleware(jwtCfg))
		protected.GET("/me", authHandler.Me)
	}
}
