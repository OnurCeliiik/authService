package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

const (
	signupPath = "/api/v1/signup"
	loginPath  = "/api/v1/login"
)

// TestSignup_success tests the signup endpoint with valid input.
func TestSignup_success(t *testing.T) {
	email := "signup-" + uuid.NewString() + "@test.com"

	w := postJSON(t, signupPath, map[string]string{
		"email":            email,
		"password":         "test-password",
		"confirm_password": "test-password",
		"first_name":       "Onur",
		"last_name":        "Çelik",
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Email != email {
		t.Fatalf("email = %q, want %q", resp.Email, email)
	}
}

// TestSignup_passwordMismatch tests the signup endpoint with a password mismatch.
func TestSignup_passwordMismatch(t *testing.T) {
	email := "signup-" + uuid.NewString() + "@test.com"

	w := postJSON(t, signupPath, map[string]string{
		"email":            email,
		"password":         "true-password",
		"confirm_password": "wrong-password",
		"first_name":       "Test",
		"last_name":        "User",
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestSignup_duplicateEmail tests the signup endpoint with a duplicate email.
func TestSignup_duplicateEmail(t *testing.T) {
	email := "duplicate-" + uuid.NewString() + "@test.com"

	body := map[string]string{
		"email":            email,
		"password":         "test-password",
		"confirm_password": "test-password",
		"first_name":       "Test",
		"last_name":        "User",
	}

	w1 := postJSON(t, signupPath, body)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first signup: %d, body: %s", w1.Code, w1.Body.String())
	}

	w2 := postJSON(t, signupPath, body)
	if w2.Code != http.StatusConflict {
		t.Fatalf("second signup: %d, body: %s", w2.Code, w2.Body.String())
	}
}

// TestSignup_shortPassword tests the signup endpoint with a short password.
func TestSignup_shortPassword(t *testing.T) {
	email := "short-password-" + uuid.NewString() + "@test.com"
	password := "short"

	body := map[string]string{
		"email":            email,
		"password":         password,
		"confirm_password": password,
		"first_name":       "Short",
		"last_name":        "Password",
	}

	w := postJSON(t, signupPath, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

}
