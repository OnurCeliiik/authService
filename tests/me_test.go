package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestMe_success(t *testing.T) {
	email := "me-" + uuid.NewString() + "@test.com"
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

	login := postJSON(t, "/api/v1/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d, body: %s", login.Code, login.Body.String())
	}

	var loginResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(login.Body).Decode(&loginResp); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var meResp struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.NewDecoder(w.Body).Decode(&meResp); err != nil {
		t.Fatal(err)
	}
	if meResp.ID == "" {
		t.Fatal("expected id in response")
	}
	if meResp.Email != email {
		t.Fatalf("email = %q, want %q", meResp.Email, email)
	}
	if meResp.FirstName != "Test" || meResp.LastName != "User" {
		t.Fatalf("unexpected name: %+v", meResp)
	}
}

func TestMe_unauthorizedWithoutToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
