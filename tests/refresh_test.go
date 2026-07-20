package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestRefresh_successAndRotates(t *testing.T) {
	email := "refresh-" + uuid.NewString() + "@test.com"
	password := "test-password"

	postJSON(t, "/api/v1/signup", map[string]string{
		"email": email, "password": password, "confirm_password": password,
		"first_name": "Test", "last_name": "User",
	})

	login := postJSON(t, "/api/v1/login", map[string]string{
		"email": email, "password": password,
	})
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d body=%s", login.Code, login.Body.String())
	}

	var loginResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(login.Body).Decode(&loginResp)
	if loginResp.RefreshToken == "" {
		t.Fatal("expected refresh_token in login response")
	}

	refresh := postJSON(t, "/api/v1/refresh", map[string]string{
		"refresh_token": loginResp.RefreshToken,
	})
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d body=%s", refresh.Code, refresh.Body.String())
	}

	var refreshResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(refresh.Body).Decode(&refreshResp)
	if refreshResp.AccessToken == "" || refreshResp.RefreshToken == "" {
		t.Fatalf("expected new token pair: %+v", refreshResp)
	}
	if refreshResp.RefreshToken == loginResp.RefreshToken {
		t.Fatal("refresh token should rotate")
	}

	reuse := postJSON(t, "/api/v1/refresh", map[string]string{
		"refresh_token": loginResp.RefreshToken,
	})
	if reuse.Code != http.StatusUnauthorized {
		t.Fatalf("old refresh should be rejected, got %d", reuse.Code)
	}

	me := getAuth(t, "/api/v1/me", refreshResp.AccessToken)
	if me.Code != http.StatusOK {
		t.Fatalf("new access token should work, got %d", me.Code)
	}
}

func TestRefresh_invalidToken(t *testing.T) {
	resp := postJSON(t, "/api/v1/refresh", map[string]string{
		"refresh_token": "not-a-real-token",
	})
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
}

func TestLogout_revokesRefreshToken(t *testing.T) {
	email := "logout-refresh-" + uuid.NewString() + "@test.com"
	password := "test-password"

	postJSON(t, "/api/v1/signup", map[string]string{
		"email": email, "password": password, "confirm_password": password,
		"first_name": "Test", "last_name": "User",
	})

	login := postJSON(t, "/api/v1/login", map[string]string{
		"email": email, "password": password,
	})
	var loginResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(login.Body).Decode(&loginResp)

	logout := postJSONAuth(t, "/api/v1/logout", loginResp.AccessToken, nil)
	if logout.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", logout.Code)
	}

	refresh := postJSON(t, "/api/v1/refresh", map[string]string{
		"refresh_token": loginResp.RefreshToken,
	})
	if refresh.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout should fail, got %d", refresh.Code)
	}
}
