package tests

import (
	"authService/internal/auth"
	"authService/internal/database"
	"authService/internal/health"
	"authService/internal/routes"
	"authService/utils/jwt"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var (
	testDB     *gorm.DB
	testRouter *gin.Engine
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	os.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5434/auth_service_test?sslmode=disable")
	os.Setenv("JWT_SECRET", "test-secret-key-32-chars-long")
	os.Setenv("JWT_TTL", "1h")
	os.Setenv("EXPOSE_RESET_TOKEN", "true")

	var err error

	testDB, err = database.OpenDB(os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}

	if err := database.Ping(testDB); err != nil {
		panic(err)
	}

	if err := database.AutoMigrate(testDB); err != nil {
		panic(err)
	}

	repo := auth.NewUserRepository(testDB)
	jwtCfg := jwt.Config{
		Secret: []byte(os.Getenv("JWT_SECRET")),
		TTL:    mustParseDuration(os.Getenv("JWT_TTL")),
	}
	svc := auth.NewAuthService(repo, jwtCfg, true)
	authHandler := auth.NewAuthHandler(svc)
	healthHandler := health.NewHandler(testDB)

	testRouter = gin.Default()
	routes.SetupRoutes(testRouter, healthHandler, authHandler, jwtCfg, repo)

	code := m.Run()
	os.Exit(code)

}

func mustParseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(err)
	}
	return d
}

func postJSON(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}
