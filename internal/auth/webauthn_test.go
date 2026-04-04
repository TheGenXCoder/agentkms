package auth_test

import (
	"testing"

	"github.com/agentkms/agentkms/internal/auth"
)

func TestNewWebAuthnService_Valid(t *testing.T) {
	_, err := auth.NewWebAuthnService(auth.WebAuthnConfig{
		RPID:      "localhost",
		RPOrigin:  "http://localhost:8080",
		DataDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
}

func TestWebAuthnStore_NewStore(t *testing.T) {
	dir := t.TempDir()
	store, err := auth.NewWebAuthnStore(dir)
	if err != nil {
		t.Fatalf("NewWebAuthnStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestWebAuthnService_BeginRegistration(t *testing.T) {
	svc, err := auth.NewWebAuthnService(auth.WebAuthnConfig{
		RPID:     "localhost",
		RPOrigin: "http://localhost:8080",
		DataDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}

	challenge, err := svc.BeginRegistration("test@team")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(challenge) == 0 {
		t.Fatal("expected non-empty challenge JSON")
	}
}

func TestWebAuthnService_BeginAuthentication_NoCreds(t *testing.T) {
	svc, _ := auth.NewWebAuthnService(auth.WebAuthnConfig{
		RPID:     "localhost",
		RPOrigin: "http://localhost:8080",
		DataDir:  t.TempDir(),
	})

	// No credentials registered — should error.
	_, err := svc.BeginAuthentication("unknown@team")
	if err == nil {
		t.Fatal("expected error when no credentials registered")
	}
}

func TestWebAuthnService_HasCredentials_EmptyFalse(t *testing.T) {
	svc, _ := auth.NewWebAuthnService(auth.WebAuthnConfig{
		RPID:     "localhost",
		RPOrigin: "http://localhost:8080",
		DataDir:  t.TempDir(),
	})
	if svc.HasCredentials("nobody@team") {
		t.Error("expected false for unregistered user")
	}
}

func TestWebAuthnService_FinishRegistration_InvalidResponse(t *testing.T) {
	svc, _ := auth.NewWebAuthnService(auth.WebAuthnConfig{
		RPID:     "localhost",
		RPOrigin: "http://localhost:8080",
		DataDir:  t.TempDir(),
	})
	// Begin first to create session.
	svc.BeginRegistration("test@team") //nolint:errcheck

	// Send garbage — should error.
	err := svc.FinishRegistration("test@team", []byte(`{"garbage":"data"}`))
	if err == nil {
		t.Fatal("expected error for invalid registration response")
	}
}

func TestWebAuthnService_FinishRegistration_NoSession(t *testing.T) {
	svc, _ := auth.NewWebAuthnService(auth.WebAuthnConfig{
		RPID:     "localhost",
		RPOrigin: "http://localhost:8080",
		DataDir:  t.TempDir(),
	})

	// No BeginRegistration called first.
	err := svc.FinishRegistration("test@team", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error when no pending session")
	}
}

func TestWebAuthnService_FinishAuthentication_NoSession(t *testing.T) {
	svc, _ := auth.NewWebAuthnService(auth.WebAuthnConfig{
		RPID:     "localhost",
		RPOrigin: "http://localhost:8080",
		DataDir:  t.TempDir(),
	})

	_, err := svc.FinishAuthentication("test@team", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error when no pending session")
	}
}
