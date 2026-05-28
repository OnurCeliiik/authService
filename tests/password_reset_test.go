package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestPasswordReset_success(t *testing.T) {
	email := "reset-" + uuid.NewString() + "@test.com"
	oldPassword := "old-password"
	newPassword := "new-password"

	signup := postJSON(t, "/api/v1/signup", map[string]string{
		"email":            email,
		"password":         oldPassword,
		"confirm_password": oldPassword,
		"first_name":       "Test",
		"last_name":        "User",
	})
	if signup.Code != http.StatusCreated {
		t.Fatalf("signup failed: %d, body: %s", signup.Code, signup.Body.String())
	}

	forgot := postJSON(t, "/api/v1/forgot-password", map[string]string{
		"email": email,
	})
	if forgot.Code != http.StatusOK {
		t.Fatalf("forgot password failed: %d, body: %s", forgot.Code, forgot.Body.String())
	}

	var forgotResp struct {
		Success    bool   `json:"success"`
		ResetToken string `json:"reset_token"`
	}
	if err := json.NewDecoder(forgot.Body).Decode(&forgotResp); err != nil {
		t.Fatal(err)
	}
	if !forgotResp.Success || forgotResp.ResetToken == "" {
		t.Fatalf("unexpected forgot response: %+v", forgotResp)
	}

	reset := postJSON(t, "/api/v1/reset-password", map[string]string{
		"token":                forgotResp.ResetToken,
		"new_password":         newPassword,
		"confirm_new_password": newPassword,
	})
	if reset.Code != http.StatusOK {
		t.Fatalf("reset password failed: %d, body: %s", reset.Code, reset.Body.String())
	}

	login := postJSON(t, "/api/v1/login", map[string]string{
		"email":    email,
		"password": newPassword,
	})
	if login.Code != http.StatusOK {
		t.Fatalf("login with new password failed: %d, body: %s", login.Code, login.Body.String())
	}
}

func TestPasswordReset_rejectsUsedToken(t *testing.T) {
	email := "reset-used-" + uuid.NewString() + "@test.com"
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

	forgot := postJSON(t, "/api/v1/forgot-password", map[string]string{
		"email": email,
	})
	if forgot.Code != http.StatusOK {
		t.Fatalf("forgot password failed: %d, body: %s", forgot.Code, forgot.Body.String())
	}

	var forgotResp struct {
		ResetToken string `json:"reset_token"`
	}
	if err := json.NewDecoder(forgot.Body).Decode(&forgotResp); err != nil {
		t.Fatal(err)
	}

	firstReset := postJSON(t, "/api/v1/reset-password", map[string]string{
		"token":                forgotResp.ResetToken,
		"new_password":         "new-password-1",
		"confirm_new_password": "new-password-1",
	})
	if firstReset.Code != http.StatusOK {
		t.Fatalf("first reset failed: %d, body: %s", firstReset.Code, firstReset.Body.String())
	}

	secondReset := postJSON(t, "/api/v1/reset-password", map[string]string{
		"token":                forgotResp.ResetToken,
		"new_password":         "new-password-2",
		"confirm_new_password": "new-password-2",
	})
	if secondReset.Code != http.StatusUnauthorized {
		t.Fatalf("second reset status = %d, want %d", secondReset.Code, http.StatusUnauthorized)
	}
}
