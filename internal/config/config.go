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
	ExposeResetToken bool
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

	exposeResetToken := strings.EqualFold(os.Getenv("EXPOSE_RESET_TOKEN"), "true")
	if !exposeResetToken && strings.EqualFold(os.Getenv("APP_ENV"), "development") {
		exposeResetToken = true
	}

	return Config{
		Port:             port,
		DatabaseURL:      databaseURL,
		JWTSecret:        secret,
		JWTTTL:           ttl,
		ExposeResetToken: exposeResetToken,
	}
}
