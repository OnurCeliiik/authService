package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestLogin_success tests the login endpoint with valid input.
func TestLogin_success(t *testing.T) {
	email := "login-" + uuid.NewString() + "@test.com"
	password := "test-password"

	signup := postJSON(t, "/api/v1/signup", map[string]string{
		"email":            email,
		"password":         password,
		"confirm_password": password,
		"first_name":       "Test",
		"last_name":        "User",
	})

	if signup.Code != http.StatusCreated {
		t.Fatalf("signup failed: %d, body: %s", signup.Code, signup.Body.String())
	}

	w := postJSON(t, "/api/v1/login", map[string]string{
		"email":    email,
		"password": password,
	})

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d, body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token_type= %q, want Bearer", resp.TokenType)
	}
}

// TestLogin_wrongPassword tests the login endpoint with a wrong password.
func TestLogin_wrongPassword(t *testing.T) {
	email := "login-" + uuid.NewString() + "@test.com"
	password := "correct-password"

	body := map[string]string{
		"email":            email,
		"password":         password,
		"confirm_password": password,
		"first_name":       "Test",
		"last_name":        "User",
	}

	w := postJSON(t, "/api/v1/signup", body)

	if w.Code != http.StatusCreated {
		t.Fatalf("signup failed: %d, body: %s", w.Code, w.Body.String())
	}

	loginBody := map[string]string{
		"email":    email,
		"password": "wrong-password",
	}

	w2 := postJSON(t, "/api/v1/login", loginBody)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w2.Code, http.StatusUnauthorized)
	}
}
