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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// reLocalhost matches any http or https origin whose host is exactly "localhost"
// with an optional port.  The regex is anchored to prevent partial matches such
// as "http://localhost.attacker.com:1234".
//
// Accepted: http://localhost, http://localhost:38291, https://localhost:8080
// Rejected: http://localhost.evil.com, http://evilocalhost:8080
var reLocalhost = regexp.MustCompile(`^https?://localhost(:\d+)?$`)

// isAllowedOrigin reports whether origin is permitted given the explicit
// allowlist and the localhost-any-port relaxation flag.
//
// Security contract:
//   - allowlist entries are matched by the go-webauthn library (case-insensitive
//     scheme+host comparison for http/https URLs, exact string otherwise).
//     We replicate that here for the allowlist path using url.Parse.
//   - When anyPort is true we additionally accept any origin whose scheme is
//     http or https and whose host is exactly "localhost" (with any port).
//     This is deliberately narrow: it does NOT accept 127.0.0.1, [::1], or
//     any subdomain of localhost.
//
// WARNING: anyPort=true is only safe in a development / CLI-callback context.
// Never enable it on a production-facing server.
func isAllowedOrigin(origin string, allowlist []string, anyPort bool) bool {
	// Check explicit allowlist first (mirrors go-webauthn's IsOriginInHaystack).
	for _, allowed := range allowlist {
		if originsEqual(origin, allowed) {
			return true
		}
	}
	// Check localhost-any-port relaxation.
	if anyPort && reLocalhost.MatchString(origin) {
		return true
	}
	return false
}

// originsEqual mirrors go-webauthn's origin comparison: for http/https URLs,
// compare scheme and host case-insensitively; for everything else use exact
// string equality.
func originsEqual(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return a == b
	}
	ub, err := url.Parse(b)
	if err != nil {
		return a == b
	}
	isHTTP := func(s string) bool { return s == "http" || s == "https" }
	if isHTTP(ua.Scheme) && isHTTP(ub.Scheme) {
		return ua.Scheme == ub.Scheme &&
			strings.EqualFold(ua.Host, ub.Host)
	}
	return a == b
}

// WebAuthnService manages FIDO2 registration and authentication.
type WebAuthnService struct {
	wa                    *webauthn.WebAuthn
	store                 *WebAuthnStore
	allowLocalhostAnyPort bool
	rpOrigins             []string // explicit allowlist (mirrors wa.Config.RPOrigins)
	rpid                  string
	rpDisplayName         string
}

// WebAuthnConfig holds configuration for the WebAuthn relying party.
type WebAuthnConfig struct {
	// RPID is the Relying Party identifier — the domain or hostname of the
	// AgentKMS server (e.g. "kms.yourdomain.com").
	RPID string

	// RPOrigins is the allowlist of permitted origins
	// (e.g. ["https://kms.yourdomain.com"]).  At least one entry is required
	// unless AllowLocalhostAnyPort is true.
	RPOrigins []string

	// RPOrigin is kept for backwards compatibility.  When non-empty and
	// RPOrigins is empty, it is promoted into RPOrigins automatically.
	//
	// Deprecated: set RPOrigins directly.
	RPOrigin string

	// AllowLocalhostAnyPort, when true, additionally accepts any origin of the
	// form http://localhost:<port> or https://localhost:<port>.  This is
	// intended exclusively for the kpm CLI local-callback WebAuthn ceremony
	// where the browser opens an ephemeral localhost port that cannot be
	// predicted at server-startup time.
	//
	// WARNING: never enable this flag on a production-facing server.  It is
	// safe only when the AgentKMS server itself is also running locally (dev
	// workstation or CI).
	AllowLocalhostAnyPort bool

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

	// Back-compat: promote the deprecated RPOrigin field.
	origins := cfg.RPOrigins
	if len(origins) == 0 && cfg.RPOrigin != "" {
		origins = []string{cfg.RPOrigin}
	}

	// The go-webauthn library (v0.16.x) does NOT expose a custom origin-verifier
	// callback.  RPOrigins is an exact allowlist (case-insensitive scheme+host
	// for http/https).  There is no wildcard or regex support.
	//
	// For AllowLocalhostAnyPort we need to add the actual request origin to the
	// library's allowlist at the moment of each ceremony call.  We do this by
	// constructing a fresh *webauthn.WebAuthn with the extended origin list in
	// waForOrigin().  The base instance below is used only for Begin* calls
	// (which do not check the origin) and as a template for per-call instances.
	//
	// When AllowLocalhostAnyPort is false, wa is used directly for all calls.
	//
	// If no explicit origins are provided but AllowLocalhostAnyPort is true we
	// still need at least one entry to satisfy go-webauthn's validation; we use
	// a placeholder that the per-call override will shadow.
	waOrigins := origins
	if len(waOrigins) == 0 {
		// Placeholder so go-webauthn accepts the config; real origin injected per call.
		waOrigins = []string{"http://localhost"}
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     waOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: init: %w", err)
	}

	store, err := NewWebAuthnStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("webauthn: store: %w", err)
	}

	return &WebAuthnService{
		wa:                    wa,
		store:                 store,
		allowLocalhostAnyPort: cfg.AllowLocalhostAnyPort,
		rpOrigins:             origins,
		rpid:                  cfg.RPID,
		rpDisplayName:         cfg.RPDisplayName,
	}, nil
}

// waForOrigin returns a *webauthn.WebAuthn appropriate for verifying a
// ceremony response whose clientDataJSON claims the given origin.
//
// When AllowLocalhostAnyPort is enabled and origin matches the localhost-any-port
// pattern, we construct a fresh *webauthn.WebAuthn that includes the specific
// port-bearing origin in its allowlist.  This is the workaround for the
// go-webauthn library's lack of a custom origin-verifier hook: we create a
// per-request library instance with the exact origin appended.
//
// For all other origins we return the shared s.wa instance unchanged.
func (s *WebAuthnService) waForOrigin(origin string) (*webauthn.WebAuthn, error) {
	if !s.allowLocalhostAnyPort || !reLocalhost.MatchString(origin) {
		return s.wa, nil
	}
	// Build the merged allowlist: explicit origins + this exact localhost origin.
	merged := make([]string, 0, len(s.rpOrigins)+1)
	merged = append(merged, s.rpOrigins...)
	// Avoid duplicates if the origin is already in the explicit list.
	alreadyPresent := false
	for _, o := range s.rpOrigins {
		if originsEqual(o, origin) {
			alreadyPresent = true
			break
		}
	}
	if !alreadyPresent {
		merged = append(merged, origin)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: s.rpDisplayName,
		RPID:          s.rpid,
		RPOrigins:     merged,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: per-call init: %w", err)
	}
	return wa, nil
}

// extractOriginFromClientDataJSON peeks at the clientDataJSON blob to extract
// the "origin" field without full verification (verification happens inside
// the library).  Returns empty string on any error — the library's own
// verification will then catch the problem.
func extractOriginFromClientDataJSON(responseJSON []byte) string {
	// clientDataJSON is nested inside the response JSON as a base64url-encoded
	// field.  However, ParseCredentialCreationResponseBytes / ParseCredentialRequestResponseBytes
	// already parse it; we need to peek BEFORE calling those.
	//
	// The response JSON has the shape:
	//   {"response": {"clientDataJSON": "<base64url>", ...}, ...}
	// We only need the origin so a quick JSON unmarshal into a partial struct is fine.
	var outer struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.Unmarshal(responseJSON, &outer); err != nil {
		return ""
	}
	cdj, err := base64.RawURLEncoding.DecodeString(outer.Response.ClientDataJSON)
	if err != nil {
		// Try standard base64 too (some browsers pad).
		cdj, err = base64.StdEncoding.DecodeString(outer.Response.ClientDataJSON)
		if err != nil {
			return ""
		}
	}
	var clientData struct {
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(cdj, &clientData); err != nil {
		return ""
	}
	return clientData.Origin
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

	// Peek at the origin so we can select the right webauthn instance when
	// AllowLocalhostAnyPort is enabled.  If the peek fails, waForOrigin("") falls
	// back to the base instance and the library's own verification catches the error.
	origin := extractOriginFromClientDataJSON(responseJSON)
	wa, err := s.waForOrigin(origin)
	if err != nil {
		return fmt.Errorf("webauthn: origin routing: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		return fmt.Errorf("webauthn: parse registration response: %w", err)
	}

	credential, err := wa.CreateCredential(user, *session, parsedResponse)
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

	// Same origin-peek-and-route as FinishRegistration.
	origin := extractOriginFromClientDataJSON(responseJSON)
	wa, err := s.waForOrigin(origin)
	if err != nil {
		return "", fmt.Errorf("webauthn: origin routing: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return "", fmt.Errorf("webauthn: parse auth response: %w", err)
	}

	_, err = wa.ValidateLogin(user, *session, parsedResponse)
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
