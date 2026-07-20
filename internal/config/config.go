package config

import (
	"log"
	"os"
	"strings"
	"time"
)

// Environment variables and configuration management

type Config struct {
	Port             string
	DatabaseURL      string
	JWTSecret        string
	JWTTTL           time.Duration
	RefreshTokenTTL  time.Duration
	ExposeResetToken bool
	AppBaseURL       string
	Email            EmailConfig
	Google           GoogleOAuthConfig
}

type EmailConfig struct {
	SMTPHost string
	SMTPPort string
	SMTPFrom string
}

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

func (g GoogleOAuthConfig) Enabled() bool {
	return g.ClientID != "" && g.ClientSecret != "" && g.RedirectURI != ""
}

func LoadConfig() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is not set")
	}

	ttlStr := os.Getenv("JWT_TTL")
	if ttlStr == "" {
		ttlStr = "24h"
	}

	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		log.Fatal("invalid JWT_TTL: ", err)
	}

	refreshTokenTTLStr := os.Getenv("REFRESH_TOKEN_TTL")
	if refreshTokenTTLStr == "" {
		refreshTokenTTLStr = "168h"
	}

	refreshTokenTTL, err := time.ParseDuration(refreshTokenTTLStr)
	if err != nil {
		log.Fatal("invalid REFRESH_TOKEN_TTL: ", err)
	}

	exposeResetToken := strings.EqualFold(os.Getenv("EXPOSE_RESET_TOKEN"), "true")
	if !exposeResetToken && strings.EqualFold(os.Getenv("APP_ENV"), "development") {
		exposeResetToken = true
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		appBaseURL = "http://localhost:" + port
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "1025"
	}
	smtpFrom := os.Getenv("SMTP_FROM")
	if smtpFrom == "" {
		smtpFrom = "noreply@authservice.local"
	}

	google := GoogleOAuthConfig{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURI:  os.Getenv("GOOGLE_REDIRECT_URI"),
	}

	return Config{
		Port:             port,
		DatabaseURL:      databaseURL,
		JWTSecret:        secret,
		JWTTTL:           ttl,
		RefreshTokenTTL:  refreshTokenTTL,
		ExposeResetToken: exposeResetToken,
		AppBaseURL:       appBaseURL,
		Email: EmailConfig{
			SMTPHost: smtpHost,
			SMTPPort: smtpPort,
			SMTPFrom: smtpFrom,
		},
		Google: google,
	}
}
