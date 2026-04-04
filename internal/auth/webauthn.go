package auth

// webauthn.go — FIDO2/WebAuthn authentication service.
//
// Allows any FIDO2 authenticator (iPhone Secure Enclave via CTAP2/BLE,
// YubiKey, Windows Hello, macOS Touch ID, Android biometrics) to authenticate
// to AgentKMS without a client certificate on disk.
//
// Flow:
//   Registration (one-time per device):
//     1. Client calls BeginRegistration → gets a challenge.
//     2. Authenticator creates a new P-256 key pair in its Secure Enclave.
//     3. Client calls FinishRegistration with the attestation response.
//     4. Server stores the public key and credential ID.
//
//   Authentication (per session):
//     1. Client calls BeginAuthentication → gets a challenge.
//     2. Authenticator signs the challenge with the Secure Enclave key.
//     3. Client calls FinishAuthentication with the assertion.
//     4. Server verifies the signature, issues an AgentKMS session token.
//
// SECURITY INVARIANTS:
//   - Private key NEVER leaves the authenticator's Secure Enclave.
//   - Each challenge is single-use (stored in memory, burned on verification).
//   - Assertions are verified with full origin + RPID binding.
//   - Credentials are stored server-side as public keys only — no private material.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnService manages FIDO2 registration and authentication.
type WebAuthnService struct {
	wa    *webauthn.WebAuthn
	store *WebAuthnStore
}

// WebAuthnConfig holds configuration for the WebAuthn relying party.
type WebAuthnConfig struct {
	// RPID is the Relying Party identifier — the domain or hostname of the
	// AgentKMS server (e.g. "kms.yourdomain.com").
	RPID string

	// RPOrigin is the origin callers will use (e.g. "https://kms.yourdomain.com").
	RPOrigin string

	// RPDisplayName is the human-readable name shown in authenticator prompts.
	RPDisplayName string

	// DataDir is where credentials are persisted.
	DataDir string
}

// NewWebAuthnService creates a WebAuthnService for the given relying party.
func NewWebAuthnService(cfg WebAuthnConfig) (*WebAuthnService, error) {
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "AgentKMS"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.RPOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: init: %w", err)
	}

	store, err := NewWebAuthnStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("webauthn: store: %w", err)
	}

	return &WebAuthnService{wa: wa, store: store}, nil
}

// ── Registration ─────────────────────────────────────────────────────────────

// BeginRegistration starts the FIDO2 registration ceremony for callerID.
// Returns a JSON blob to send to the client (navigator.credentials.create options).
func (s *WebAuthnService) BeginRegistration(callerID string) ([]byte, error) {
	user := s.store.userFor(callerID)

	creation, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin registration: %w", err)
	}

	if err := s.store.SaveSession(callerID, "reg", session); err != nil {
		return nil, fmt.Errorf("webauthn: save session: %w", err)
	}

	return json.Marshal(creation)
}

// FinishRegistration completes the FIDO2 registration ceremony.
// responseJSON is the JSON from the client's PublicKeyCredential.
func (s *WebAuthnService) FinishRegistration(callerID string, responseJSON []byte) error {
	user := s.store.userFor(callerID)

	session, err := s.store.GetSession(callerID, "reg")
	if err != nil {
		return fmt.Errorf("webauthn: no pending registration session for %q", callerID)
	}
	defer s.store.DeleteSession(callerID, "reg")

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		return fmt.Errorf("webauthn: parse registration response: %w", err)
	}

	credential, err := s.wa.CreateCredential(user, *session, parsedResponse)
	if err != nil {
		return fmt.Errorf("webauthn: create credential: %w", err)
	}

	return s.store.SaveCredential(callerID, credential)
}

// ── Authentication ────────────────────────────────────────────────────────────

// BeginAuthentication starts the FIDO2 authentication ceremony for callerID.
// Returns a JSON blob to send to the client (navigator.credentials.get options).
func (s *WebAuthnService) BeginAuthentication(callerID string) ([]byte, error) {
	user := s.store.userFor(callerID)

	options, session, err := s.wa.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin login: %w", err)
	}

	if err := s.store.SaveSession(callerID, "auth", session); err != nil {
		return nil, fmt.Errorf("webauthn: save session: %w", err)
	}

	return json.Marshal(options)
}

// FinishAuthentication verifies a FIDO2 assertion and returns the callerID on success.
func (s *WebAuthnService) FinishAuthentication(callerID string, responseJSON []byte) (string, error) {
	user := s.store.userFor(callerID)

	session, err := s.store.GetSession(callerID, "auth")
	if err != nil {
		return "", fmt.Errorf("webauthn: no pending auth session for %q", callerID)
	}
	defer s.store.DeleteSession(callerID, "auth")

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return "", fmt.Errorf("webauthn: parse auth response: %w", err)
	}

	_, err = s.wa.ValidateLogin(user, *session, parsedResponse)
	if err != nil {
		return "", fmt.Errorf("webauthn: validate login: %w", err)
	}

	return callerID, nil
}

// HasCredentials reports whether callerID has any registered FIDO2 credentials.
func (s *WebAuthnService) HasCredentials(callerID string) bool {
	return len(s.store.userFor(callerID).WebAuthnCredentials()) > 0
}

// ── WebAuthnStore ─────────────────────────────────────────────────────────────

// WebAuthnStore persists FIDO2 credentials and in-progress sessions.
type WebAuthnStore struct {
	mu          sync.RWMutex
	dataDir     string
	credentials map[string][]webauthn.Credential // callerID → credentials
	sessions    map[string]*webauthn.SessionData // "callerID:kind" → session
}

// NewWebAuthnStore creates a WebAuthnStore backed by dataDir.
func NewWebAuthnStore(dataDir string) (*WebAuthnStore, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("webauthn store: mkdir: %w", err)
	}
	s := &WebAuthnStore{
		dataDir:     dataDir,
		credentials: make(map[string][]webauthn.Credential),
		sessions:    make(map[string]*webauthn.SessionData),
	}
	_ = s.load() // ignore not-found
	return s, nil
}

func (s *WebAuthnStore) userFor(callerID string) *waUser {
	s.mu.RLock()
	creds := s.credentials[callerID]
	s.mu.RUnlock()
	return &waUser{id: callerID, credentials: creds}
}

func (s *WebAuthnStore) SaveCredential(callerID string, cred *webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[callerID] = append(s.credentials[callerID], *cred)
	return s.persist()
}

func (s *WebAuthnStore) SaveSession(callerID, kind string, session *webauthn.SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[callerID+":"+kind] = session
	return nil
}

func (s *WebAuthnStore) GetSession(callerID, kind string) (*webauthn.SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[callerID+":"+kind]
	if !ok {
		return nil, errors.New("webauthn: session not found")
	}
	return sess, nil
}

func (s *WebAuthnStore) DeleteSession(callerID, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, callerID+":"+kind)
}

func (s *WebAuthnStore) path() string {
	return filepath.Join(s.dataDir, "webauthn-credentials.json")
}

func (s *WebAuthnStore) persist() error {
	data, err := json.MarshalIndent(s.credentials, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}

func (s *WebAuthnStore) load() error {
	data, err := os.ReadFile(s.path())
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.credentials)
}

// ── waUser implements webauthn.User ──────────────────────────────────────────

type waUser struct {
	id          string
	credentials []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte {
	// Use a stable byte representation of the callerID as the user handle.
	return []byte(u.id)
}

func (u *waUser) WebAuthnName() string                       { return u.id }
func (u *waUser) WebAuthnDisplayName() string                { return u.id }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// ── helpers ───────────────────────────────────────────────────────────────────
