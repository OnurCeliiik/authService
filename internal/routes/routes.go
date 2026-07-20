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
		var public []gin.HandlerFunc
		if gin.Mode() != gin.TestMode {
			public = append(public, middleware.RateLimitByIP(30, time.Minute))
		}

		v1.POST("/signup", append(public, authHandler.Signup)...)
		v1.POST("/login", append(public, authHandler.Login)...)
		v1.POST("/refresh", append(public, authHandler.Refresh)...)
		v1.POST("/reset-password", append(public, authHandler.ResetPassword)...)
		v1.POST("/forgot-password", append(public, authHandler.ForgotPassword)...)

		v1.GET("/oauth/google", authHandler.GoogleOAuth)
		v1.GET("/oauth/google/callback", authHandler.GoogleCallback)

		protected := v1.Group("")
		protected.Use(middleware.AuthMiddleware(jwtCfg, tokenVersions))
		protected.GET("/me", authHandler.Me)
		protected.PATCH("/me", authHandler.UpdateMe)
		protected.POST("/change-password", authHandler.ChangePassword)
		protected.POST("/logout", authHandler.LogOut)
	}
}
