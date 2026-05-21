package main

import (
	"authService/internal/auth"
	"authService/internal/config"
	"authService/internal/database"
	"authService/internal/health"
	"authService/internal/routes"
	"authService/utils/jwt"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	log.Println("Starting auth service...")

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("failed to load environment variables: ", err)
	}

	// Load configuration
	cfg := config.LoadConfig()

	// Open database connection
	db, err := database.OpenDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("failed to open database: ", err)
	}

	// Ping database
	if err := database.Ping(db); err != nil {
		log.Fatal("ping database failed: ", err)
	}

	// Auto migrate database
	if err := database.AutoMigrate(db); err != nil {
		log.Fatal("failed to auto migrate database: ", err)
	}

	repo := auth.NewUserRepository(db)
	svc := auth.NewAuthService(repo, jwt.Config{Secret: []byte(cfg.JWTSecret), TTL: cfg.JWTTTL})
	authHandler := auth.NewAuthHandler(svc)
	healthHandler := health.NewHandler(db)

	router := gin.Default()
	routes.SetupRoutes(router, healthHandler, authHandler)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Println("listening on port", addr)

	if err := router.Run(addr); err != nil {
		log.Fatal("failed to start server: ", err)
	}

}
