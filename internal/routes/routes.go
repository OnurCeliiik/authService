package routes

import (
	"authService/internal/auth"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(
	router *gin.Engine,
	authHandler *auth.AuthHandler,
) {

	api := router.Group("/api")

	v1 := api.Group("v1")
	{

		v1.POST("/signup", authHandler.Signup)
		v1.POST("/login", authHandler.Login)
	}
}
