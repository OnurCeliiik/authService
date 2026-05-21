package routes

import (
	"authService/internal/auth"
	"authService/internal/health"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(
	router *gin.Engine,
	healthHandler *health.Handler,
	authHandler *auth.AuthHandler,
) {
	router.GET("/health", healthHandler.Health)

	v1 := router.Group("/api/v1")
	{
		v1.POST("/signup", authHandler.Signup)
		v1.POST("/login", authHandler.Login)
	}
}
