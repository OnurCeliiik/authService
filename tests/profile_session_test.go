package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestChangePassword_successAndInvalidatesJWT(t *testing.T) {
	email := "change-pw-" + uuid.NewString() + "@test.com"
	oldPassword := "old-password"
	newPassword := "new-password"

	signup := postJSON(t, "/api/v1/signup", map[string]string{
		"email": email, "password": oldPassword, "confirm_password": oldPassword,
		"first_name": "Test", "last_name": "User",
	})
	if signup.Code != http.StatusCreated {
		t.Fatalf("signup failed: %d", signup.Code)
	}

	login := postJSON(t, "/api/v1/login", map[string]string{
		"email": email, "password": oldPassword,
	})
	var loginResp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(login.Body).Decode(&loginResp)

	change := postJSONAuth(t, "/api/v1/change-password", loginResp.AccessToken, map[string]string{
		"current_password":     oldPassword,
		"new_password":         newPassword,
		"confirm_new_password": newPassword,
	})
	if change.Code != http.StatusOK {
		t.Fatalf("change password failed: %d body=%s", change.Code, change.Body.String())
	}

	me := getAuth(t, "/api/v1/me", loginResp.AccessToken)
	if me.Code != http.StatusUnauthorized {
		t.Fatalf("old JWT should be rejected after change password, got %d", me.Code)
	}

	relogin := postJSON(t, "/api/v1/login", map[string]string{
		"email": email, "password": newPassword,
	})
	if relogin.Code != http.StatusOK {
		t.Fatalf("login with new password failed: %d", relogin.Code)
	}
}

func TestChangePassword_wrongCurrentPassword(t *testing.T) {
	email := "change-pw-bad-" + uuid.NewString() + "@test.com"
	password := "test-password"

	postJSON(t, "/api/v1/signup", map[string]string{
		"email": email, "password": password, "confirm_password": password,
		"first_name": "Test", "last_name": "User",
	})
	login := postJSON(t, "/api/v1/login", map[string]string{
		"email": email, "password": password,
	})
	var loginResp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(login.Body).Decode(&loginResp)

	change := postJSONAuth(t, "/api/v1/change-password", loginResp.AccessToken, map[string]string{
		"current_password":     "wrong-password",
		"new_password":         "new-password",
		"confirm_new_password": "new-password",
	})
	if change.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d body=%s", change.Code, http.StatusUnauthorized, change.Body.String())
	}
}

func TestUpdateMe_success(t *testing.T) {
	email := "update-me-" + uuid.NewString() + "@test.com"
	password := "test-password"

	postJSON(t, "/api/v1/signup", map[string]string{
		"email": email, "password": password, "confirm_password": password,
		"first_name": "Test", "last_name": "User",
	})
	login := postJSON(t, "/api/v1/login", map[string]string{
		"email": email, "password": password,
	})
	var loginResp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(login.Body).Decode(&loginResp)

	patch := patchJSONAuth(t, "/api/v1/me", loginResp.AccessToken, map[string]string{
		"first_name": "Updated",
		"last_name":  "Name",
	})
	if patch.Code != http.StatusOK {
		t.Fatalf("update me failed: %d body=%s", patch.Code, patch.Body.String())
	}

	var resp struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	_ = json.NewDecoder(patch.Body).Decode(&resp)
	if resp.Email != email || resp.FirstName != "Updated" || resp.LastName != "Name" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestUpdateMe_requiresAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/me", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLogout_invalidatesJWT(t *testing.T) {
	email := "logout-" + uuid.NewString() + "@test.com"
	password := "test-password"

	postJSON(t, "/api/v1/signup", map[string]string{
		"email": email, "password": password, "confirm_password": password,
		"first_name": "Test", "last_name": "User",
	})
	login := postJSON(t, "/api/v1/login", map[string]string{
		"email": email, "password": password,
	})
	var loginResp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(login.Body).Decode(&loginResp)

	logout := postJSONAuth(t, "/api/v1/logout", loginResp.AccessToken, nil)
	if logout.Code != http.StatusOK {
		t.Fatalf("logout failed: %d body=%s", logout.Code, logout.Body.String())
	}

	me := getAuth(t, "/api/v1/me", loginResp.AccessToken)
	if me.Code != http.StatusUnauthorized {
		t.Fatalf("JWT should be rejected after logout, got %d", me.Code)
	}
}
