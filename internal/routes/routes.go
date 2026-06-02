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
	tokenVersions middleware.TokenVersionChecker,
) {
	router.GET("/health", healthHandler.Health)

	v1 := router.Group("/api/v1")
	{
		authRateLimit := middleware.RateLimitByIP(30, time.Minute)
		v1.POST("/signup", authRateLimit, authHandler.Signup)
		v1.POST("/login", authRateLimit, authHandler.Login)
		v1.POST("/reset-password", authRateLimit, authHandler.ResetPassword)
		v1.POST("/forgot-password", authRateLimit, authHandler.ForgotPassword)

		protected := v1.Group("")
		protected.Use(middleware.AuthMiddleware(jwtCfg, tokenVersions))
		protected.GET("/me", authHandler.Me)
	}
}
