package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestBootstrapLoginAuthenticateAndLogout(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "sophon.db"))
	if err != nil {
		t.Fatalf("Open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	service := NewService(db, time.Hour, false, "admin", "secret-password")
	password, err := service.Bootstrap(context.Background())
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if password != "secret-password" {
		t.Fatalf("bootstrap password = %q", password)
	}

	result, err := service.Login(context.Background(), "admin", "secret-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Token == "" || result.CSRFToken == "" {
		t.Fatal("login did not return tokens")
	}

	authSession, err := service.Authenticate(context.Background(), result.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if authSession.User.Username != "admin" || authSession.User.Role != "admin" {
		t.Fatalf("unexpected user: %#v", authSession.User)
	}
	if !service.ValidateCSRF(authSession, result.CSRFToken) {
		t.Fatal("valid CSRF token rejected")
	}
	if service.ValidateCSRF(authSession, "wrong-token") {
		t.Fatal("invalid CSRF token accepted")
	}

	if _, err := service.Login(context.Background(), "admin", "wrong-password"); err != ErrInvalidCredentials {
		t.Fatalf("wrong password error = %v", err)
	}

	if err := service.Logout(context.Background(), result.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := service.Authenticate(context.Background(), result.Token); err != ErrUnauthorized {
		t.Fatalf("session should be invalid after logout: %v", err)
	}
}
