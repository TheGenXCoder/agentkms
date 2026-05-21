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
	"encoding/base64"
	"encoding/hex"
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

// NewWebAuthnServiceFromStore creates a WebAuthnService backed by an existing
// WebAuthnStore, without requiring a live WebAuthn relying-party configuration.
//
// The returned service supports ListCredentials and DeleteCredential but does
// NOT support registration or authentication ceremonies (those require a fully
// configured go-webauthn instance).  Use this in tests and in contexts where
// only credential management — not new FIDO2 ceremonies — is needed.
func NewWebAuthnServiceFromStore(store *WebAuthnStore) (*WebAuthnService, error) {
	if store == nil {
		return nil, fmt.Errorf("webauthn: NewWebAuthnServiceFromStore: store must not be nil")
	}
	return &WebAuthnService{wa: nil, store: store}, nil
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

// CredentialMeta is the metadata shape returned by ListCredentials.
// Optional fields (Name, AuthenticatorType, CreatedAt, LastUsedAt, AAGUID) are
// left empty when the underlying store does not track them.
type CredentialMeta struct {
	// ID is the base64url-encoded credential ID.
	ID string

	// Name is a human-friendly label; empty when not set.
	Name string

	// AuthenticatorType is "platform", "cross-platform", or "" when unknown.
	AuthenticatorType string

	// CreatedAt is an RFC 3339 timestamp, or "" when not tracked.
	CreatedAt string

	// LastUsedAt is an RFC 3339 timestamp, or "" when not tracked.
	LastUsedAt string

	// AAGUID is the hex-encoded authenticator AAGUID, or "" when all-zero.
	AAGUID string
}

// ListCredentials returns metadata for every FIDO2 credential bound to callerID.
func (s *WebAuthnService) ListCredentials(callerID string) ([]CredentialMeta, error) {
	return s.store.ListCredentials(callerID)
}

// DeleteCredential removes the credential with the given base64url-encoded ID
// from callerID's credential set.
//
// Returns ErrCredentialNotFound when no such credential exists.
// The caller is responsible for verifying ownership before calling this method.
func (s *WebAuthnService) DeleteCredential(callerID, credIDBase64 string) error {
	return s.store.DeleteCredential(callerID, credIDBase64)
}

// ErrCredentialNotFound is returned by DeleteCredential when the credential ID
// does not exist in the store.
var ErrCredentialNotFound = errors.New("webauthn: credential not found")

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

// ListCredentials returns metadata for every credential registered to callerID.
// The underlying store does not track created_at, last_used_at, or names —
// those optional fields are returned as empty strings.
func (s *WebAuthnStore) ListCredentials(callerID string) ([]CredentialMeta, error) {
	s.mu.RLock()
	creds := s.credentials[callerID]
	s.mu.RUnlock()

	result := make([]CredentialMeta, 0, len(creds))
	for _, c := range creds {
		meta := CredentialMeta{
			ID:                base64.RawURLEncoding.EncodeToString(c.ID),
			AuthenticatorType: string(c.Authenticator.Attachment),
			// CreatedAt and LastUsedAt: not tracked by the store; return "".
			// Name: not tracked; return "".
		}
		// AAGUID: omit if all-zero (many authenticators report a zero AAGUID
		// when in a privacy-preserving mode — emitting it as-is would be
		// misleading).
		if !allZero(c.Authenticator.AAGUID) {
			meta.AAGUID = hex.EncodeToString(c.Authenticator.AAGUID)
		}
		result = append(result, meta)
	}
	return result, nil
}

// allZero reports whether b is empty or contains only zero bytes.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// DeleteCredential removes the credential with the given base64url-encoded ID
// from callerID's set and persists the updated set to disk.
// Returns ErrCredentialNotFound if no match exists.
func (s *WebAuthnStore) DeleteCredential(callerID, credIDBase64 string) error {
	targetID, err := base64.RawURLEncoding.DecodeString(credIDBase64)
	if err != nil {
		return ErrCredentialNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	creds, ok := s.credentials[callerID]
	if !ok {
		return ErrCredentialNotFound
	}

	idx := -1
	for i, c := range creds {
		if string(c.ID) == string(targetID) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ErrCredentialNotFound
	}

	// Remove by swapping with the last element and truncating.
	creds[idx] = creds[len(creds)-1]
	s.credentials[callerID] = creds[:len(creds)-1]
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
