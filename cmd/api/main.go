package main

import (
	"authService/internal/auth"
	"authService/internal/config"
	"authService/internal/database"
	"authService/internal/email"
	"authService/internal/health"
	"authService/internal/routes"
	"authService/utils/jwt"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
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

	var mail email.Sender
	if cfg.Email.SMTPHost != "" {
		mail = email.NewSMTPSender(
			cfg.Email.SMTPHost,
			cfg.Email.SMTPPort,
			cfg.Email.SMTPFrom,
		)
		log.Println("email: using SMTP at", cfg.Email.SMTPHost+":"+cfg.Email.SMTPPort)
	} else {
		mail = email.NewLogSender()
		log.Println("email: using log sender (SMTP_HOST not set)")
	}

	repo := auth.NewUserRepository(db)
	jwtCfg := jwt.Config{Secret: []byte(cfg.JWTSecret), TTL: cfg.JWTTTL}
	svc := auth.NewAuthService(repo, jwtCfg, cfg.RefreshTokenTTL, cfg.ExposeResetToken, mail, cfg.AppBaseURL)

	var googleCfg *oauth2.Config
	if cfg.Google.Enabled() {
		googleCfg = auth.NewGoogleOAuth(
			cfg.Google.ClientID,
			cfg.Google.ClientSecret,
			cfg.Google.RedirectURI,
		)
		log.Println("google oauth: enabled")
	} else {
		log.Println("google oauth: disabled (missing GOOGLE_* env)")
	}

	authHandler := auth.NewAuthHandler(svc, googleCfg)
	healthHandler := health.NewHandler(db)

	router := gin.Default()
	routes.SetupRoutes(router, healthHandler, authHandler, jwtCfg, repo)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Println("listening on port", addr)

	if err := router.Run(addr); err != nil {
		log.Fatal("failed to start server: ", err)
	}

}
