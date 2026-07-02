// Package devserver wires enrollment routes for local AgentKMS (dev + bare-metal prod).
package devserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/bootstrap"
	"github.com/agentkms/agentkms/internal/invite"
	"github.com/agentkms/agentkms/internal/pki"
)

// WireEnrollment adds bootstrap-token enrollment, CA publication, and remote
// invite minting to a dev server mux.
func WireEnrollment(mux *http.ServeMux, dataDir string, authHandler *api.AuthHandler, tokenSvc *auth.TokenService) error {
	signer, err := pki.LoadLocalSigner(dataDir)
	if err != nil {
		return fmt.Errorf("enrollment wiring: %w", err)
	}
	storeDir := filepath.Join(dataDir, "bootstrap-tokens")
	store, err := bootstrap.NewFileStore(storeDir)
	if err != nil {
		return err
	}
	authHandler.SetPKI(signer, nil)
	authHandler.SetBootstrapStore(store)

	mux.HandleFunc("POST /auth/cert/issue", authHandler.HandleCertIssue)
	mux.HandleFunc("GET /auth/cert/list", authHandler.HandleCertList)
	mux.HandleFunc("GET /.well-known/agentkms-ca", func(w http.ResponseWriter, r *http.Request) {
		caPEM, err := pki.ReadCAPEM(dataDir)
		if err != nil {
			http.Error(w, "CA not available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})

	// Remote invite minting: an enrolled admin runs `kpm admin inviteuser <name>`
	// from their own machine; the server mints a bootstrap token and returns a
	// self-contained kpmi1_ invite code (server URL + CA pin + token).
	mux.Handle("POST /admin/invites",
		auth.RequireToken(tokenSvc)(http.HandlerFunc(handleAdminInvite(dataDir, store))))

	return nil
}

// handleAdminInvite mints a kpmi1_ invite code for a username.
// Auth: valid mTLS session token (enforced by RequireToken upstream).
func handleAdminInvite(dataDir string, store auth.BootstrapStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var in struct {
			Username   string `json:"username"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Username) == "" {
			http.Error(w, `{"error":"username required in body"}`, http.StatusBadRequest)
			return
		}
		username := strings.TrimSpace(in.Username)
		ttl := 24 * time.Hour
		if in.TTLSeconds > 0 {
			ttl = time.Duration(in.TTLSeconds) * time.Second
		}

		rawToken, err := store.Create(r.Context(), auth.BootstrapRecord{
			UserID:            username,
			DeviceNamePattern: "*",
			ExpiresAt:         time.Now().UTC().Add(ttl),
		})
		if err != nil {
			slog.Error("admin invite: bootstrap create failed", "error", err)
			http.Error(w, `{"error":"failed to create invite"}`, http.StatusInternalServerError)
			return
		}

		fp, err := pki.Fingerprint(filepath.Join(dataDir, "ca.crt"))
		if err != nil {
			slog.Error("admin invite: CA fingerprint failed", "error", err)
			http.Error(w, `{"error":"CA not available"}`, http.StatusInternalServerError)
			return
		}

		// Server URL: the address the admin used to reach us is routable for
		// invitees on the same network path.
		serverURL := "https://" + r.Host

		expiresAt := time.Now().Add(ttl)
		code, err := invite.Encode(invite.Payload{
			Version:       1,
			ServerURL:     serverURL,
			CAFingerprint: fp,
			Token:         rawToken,
			UserID:        username,
			ExpiresAt:     expiresAt.Unix(),
		})
		if err != nil {
			http.Error(w, `{"error":"failed to encode invite"}`, http.StatusInternalServerError)
			return
		}

		slog.Info("admin: issued invite code", "for_user", username, "expires_at", expiresAt.Format(time.RFC3339))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"invite_code": code,
			"username":    username,
			"expires_at":  expiresAt.Format(time.RFC3339),
		})
	}
}

// EnforceDevBind rejects non-loopback listen addresses in dev mode.
func EnforceDevBind(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("dev mode must bind loopback only (got %q)", host)
	}
	return nil
}
