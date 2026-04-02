package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// TokenTTL is the lifetime of a freshly issued session token.
// Proactive refresh should be triggered at TokenTTL - 5 minutes.
const TokenTTL = 15 * time.Minute

// tokenVersion is the current token format version.  Changing this value
// invalidates all previously issued tokens (intended for breaking changes only).
const tokenVersion = 1

// ── Claims ────────────────────────────────────────────────────────────────────

// tokenClaims is the JSON payload embedded in a session token.
//
// SECURITY INVARIANT: This struct must never contain key material, plaintext,
// or LLM API credentials.  CallerID and TeamID are identity metadata only.
type tokenClaims struct {
	// V is the token format version.  Tokens with an unknown version are rejected.
	V int `json:"v"`
	// JTI is the token's unique identifier.  Used for revocation lookups.
	JTI string `json:"jti"`
	// Sub is the CallerID from the mTLS certificate CN.
	Sub string `json:"sub"`
	// TID is the TeamID from the mTLS certificate O field.
	TID string `json:"tid"`
	// SID is the per-Pi-session identifier.  Correlates all operations
	// within a single session in the audit trail.
	SID string `json:"sid"`
	// CSN is the Certificate Serial Number in hex format.
	// Used for strong binding to the exact certificate.
	CSN string `json:"csn"`
	// CFP is a Certificate Fingerprint (SHA-256 of the DER-encoded cert).
	// Used for strong binding to prevent token replay with different certs.
	CFP string `json:"cfp"`
	// IAT is the Unix timestamp (seconds) when the token was issued.
	IAT int64 `json:"iat"`
	// EXP is the Unix timestamp (seconds) when the token expires.
	EXP int64 `json:"exp"`
}

// ── Token ─────────────────────────────────────────────────────────────────────

// Token is a validated, decoded session token.  It is produced by
// TokenStore.Validate and carries the caller's identity for use in
// downstream policy checks and audit logging.
type Token struct {
	// TokenID is the unique identifier for this token.  Used for revocation.
	TokenID string

	// CallerID is the authenticated caller identity (from the mTLS cert CN).
	CallerID string

	// TeamID is the team that owns this caller (from the mTLS cert O field).
	TeamID string

	// SessionID is the per-Pi-session identifier for this token.
	SessionID string

	// CertSerial is the certificate serial number in hex.
	CertSerial string

	// CertFingerprint is a hash of the client certificate.
	CertFingerprint string

	// ExpiresAt is when this token expires.
	ExpiresAt time.Time

	// Identity is a convenience copy of the caller's Identity, reconstructed
	// from the token claims.  Role and SPIFFEID are not persisted in tokens
	// (they are re-derived from the certificate on each session start); they
	// will be zero values in tokens issued after the initial /auth/session call.
	Identity *identity.Identity
}

// ── TokenStore ────────────────────────────────────────────────────────────────

// TokenStore manages session token issuance, validation, and revocation.
//
// The HMAC signing key is generated at construction time from crypto/rand and
// exists only in process memory.  Restarting the server invalidates all
// previously issued tokens (acceptable for the 15-minute TTL design).
//
// Concurrency: all methods are safe for concurrent use.
type TokenStore struct {
	signingKey []byte // 32 random bytes; NEVER exposed via any method or log
	mu         sync.RWMutex
	revoked    map[string]time.Time // tokenID → expiry (for cleanup)
}

// NewTokenStore creates a TokenStore with a freshly generated HMAC signing key.
// Returns an error only if the OS entropy source is unavailable.
func NewTokenStore() (*TokenStore, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("auth: generating token signing key: %w", err)
	}
	return &TokenStore{
		signingKey: key,
		revoked:    make(map[string]time.Time),
	}, nil
}

// Issue creates, signs, and returns a new session token for the given identity.
//
// Returns the raw token string (to be sent to the caller as Bearer token),
// the decoded Token (for immediate use in the handler), and any error.
//
// SECURITY: The raw token string must be transmitted only over mTLS.  It must
// not be written to logs, stored in environment variables, or included in
// error responses.
func (ts *TokenStore) Issue(id *identity.Identity) (tokenStr string, tok *Token, err error) {
	tokenID, err := randomHex(16)
	if err != nil {
		return "", nil, fmt.Errorf("auth: generate token ID: %w", err)
	}
	sessionID, err := randomHex(16)
	if err != nil {
		return "", nil, fmt.Errorf("auth: generate session ID: %w", err)
	}

	now := time.Now().UTC()
	exp := now.Add(TokenTTL)

	// Create a SHA-256 hash of the client certificate if available
	var certFingerprint string
	if id.CertFingerprint == "" && id.Certificate != nil {
		// Calculate a fingerprint if not already present
		certDER := id.Certificate.Raw
		certHash := sha256.Sum256(certDER)
		certFingerprint = hex.EncodeToString(certHash[:])
	} else {
		// Use the existing fingerprint if available
		certFingerprint = id.CertFingerprint
	}

	claims := tokenClaims{
		V:   tokenVersion,
		JTI: tokenID,
		Sub: id.CallerID,
		TID: id.TeamID,
		SID: sessionID,
		CSN: id.CertSerial,
		CFP: certFingerprint,
		IAT: now.Unix(),
		EXP: exp.Unix(),
	}

	tokenStr, err = ts.encode(claims)
	if err != nil {
		return "", nil, fmt.Errorf("auth: encode token: %w", err)
	}

	tok = &Token{
		TokenID:        tokenID,
		CallerID:       id.CallerID,
		TeamID:         id.TeamID,
		SessionID:      sessionID,
		CertSerial:     id.CertSerial,
		CertFingerprint: certFingerprint,
		ExpiresAt:      exp,
		Identity: &identity.Identity{
			CallerID:       id.CallerID,
			TeamID:         id.TeamID,
			Role:           id.Role,
			SPIFFEID:       id.SPIFFEID,
			CertSerial:     id.CertSerial,
			CertFingerprint: certFingerprint,
		},
	}
	return tokenStr, tok, nil
}

// Validate parses and validates a raw token string.
//
// Validation checks (all must pass):
//  1. HMAC signature is correct
//  2. Token version is known
//  3. Token is not expired
//  4. Token is not in the revocation list
//  5. If mtlsCallerID is non-empty: token subject matches the mTLS cert CN
//     (connection binding — prevents replay on a different mTLS connection)
//  6. If both the token's CFP and the connection's cert fingerprint are
//     non-empty: they must match (prevents replay with a different cert).
//
// cs is the TLS connection state for the current request.  Pass r.TLS
// directly from the HTTP handler — this avoids the global-variable race
// that would exist if the state were communicated via a package-level var.
// Pass nil in tests that do not exercise TLS (binding checks are skipped).
//
// Returns the decoded Token on success, or a non-nil error describing the
// failure.  Error messages are intentionally vague to avoid leaking internal
// state to an attacker.
func (ts *TokenStore) Validate(tokenStr, mtlsCallerID string, cs *tls.ConnectionState) (*Token, error) {
	claims, err := ts.decode(tokenStr)
	if err != nil {
		// Do not forward err details to the caller — they may reveal token
		// format information useful for forgery attempts.
		return nil, errors.New("auth: invalid token")
	}

	now := time.Now().UTC().Unix()
	if now > claims.EXP {
		// Collapsed to the same generic error as invalid-token to prevent
		// callers from distinguishing expiry from signature failure (oracle).
		return nil, errors.New("auth: invalid token")
	}

	// Derive the certificate fingerprint from the VERIFIED chain in the TLS state.
	// Using the passed-in cs (not a global) eliminates the per-request data race
	// that would occur if multiple goroutines wrote to a package-level variable.
	//
	// SECURITY: Use cs.VerifiedChains[0][0], NOT cs.PeerCertificates[0].
	// PeerCertificates is the raw peer-presented chain with no verification
	// guarantee.  VerifiedChains is populated only after Go’s TLS stack
	// successfully verified the chain against the CA pool.  All other functions
	// in this package that read cert identity use VerifiedChains; using
	// PeerCertificates here would create an inconsistency that could allow
	// a fingerprint mismatch under non-standard TLS configurations.
	var mtlsCertFingerprint string
	if cs != nil && len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
		cert := cs.VerifiedChains[0][0]
		certHash := sha256.Sum256(cert.Raw)
		mtlsCertFingerprint = hex.EncodeToString(certHash[:])
	}

	// Connection binding has two components:
	// 1. The token's subject (CallerID) must match the mTLS cert CN
	// 2. The token's certificate fingerprint must match the current connection's cert
	// Skip the checks only when mtlsCallerID is empty (e.g., in unit tests
	// that bypass TLS; never skip in production).
	// Connection binding: caller identity and cert must match what was in
	// the token at issuance time.  All failure paths return the same generic
	// error — callers (middleware) must not distinguish wrong-cert, expired,
	// or revoked from bad-signature (oracle prevention).
	if mtlsCallerID != "" {
		if claims.Sub != mtlsCallerID {
			return nil, errors.New("auth: invalid token")
		}
		if claims.CFP != "" && mtlsCertFingerprint != "" && claims.CFP != mtlsCertFingerprint {
			return nil, errors.New("auth: invalid token")
		}
	}

	if ts.isRevoked(claims.JTI) {
		return nil, errors.New("auth: invalid token")
	}

	tok := &Token{
		TokenID:        claims.JTI,
		CallerID:       claims.Sub,
		TeamID:         claims.TID,
		SessionID:      claims.SID,
		CertSerial:     claims.CSN,
		CertFingerprint: claims.CFP,
		ExpiresAt:      time.Unix(claims.EXP, 0).UTC(),
		Identity: &identity.Identity{
			CallerID:       claims.Sub,
			TeamID:         claims.TID,
			CertSerial:     claims.CSN,
			CertFingerprint: claims.CFP,
		},
	}
	return tok, nil
}

// Revoke adds the token to the in-memory revocation list.  Subsequent calls
// to Validate with this token will return an error immediately.
//
// Revoke is best-effort on a goroutine level but atomic with respect to
// concurrent Validate calls: once Revoke returns, no subsequent Validate call
// for the same token will succeed.
//
// Returns an error if tokenStr is not a valid signed token (the MAC is
// verified before adding to the blocklist to prevent DoS via large lists).
func (ts *TokenStore) Revoke(tokenStr string) error {
	claims, err := ts.decode(tokenStr)
	if err != nil {
		return fmt.Errorf("auth: revoke: invalid token: %w", err)
	}

	ts.mu.Lock()
	ts.revoked[claims.JTI] = time.Unix(claims.EXP, 0).UTC()
	ts.mu.Unlock()
	return nil
}

// PurgeExpired removes tokens from the revocation list whose expiry has
// already passed.  These entries are no longer needed because an expired token
// is rejected by Validate before the revocation check.
//
// Intended to be called periodically (e.g., every TokenTTL interval) to
// bound the memory usage of the revocation list.
func (ts *TokenStore) PurgeExpired() {
	now := time.Now().UTC()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for id, exp := range ts.revoked {
		if now.After(exp) {
			delete(ts.revoked, id)
		}
	}
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

// encode serialises claims to JSON, base64url-encodes the payload, appends
// a dot separator, then appends the base64url-encoded HMAC-SHA256 of the
// encoded payload.
//
// Token format: <base64url(json(claims))>.<base64url(hmac-sha256)>
//
// The HMAC covers the encoded payload (not the raw JSON) to ensure that
// any change to the encoding is also detected.
func (ts *TokenStore) encode(claims tokenClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := ts.computeMAC(encodedPayload)
	encodedMAC := base64.RawURLEncoding.EncodeToString(mac)
	return encodedPayload + "." + encodedMAC, nil
}

// decode validates the token MAC (constant-time) and decodes the claims.
// Returns an error for any of: malformed format, bad MAC, unknown version.
func (ts *TokenStore) decode(tokenStr string) (*tokenClaims, error) {
	if tokenStr == "" {
		return nil, errors.New("empty token")
	}
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed token: missing separator")
	}
	encodedPayload, encodedMAC := parts[0], parts[1]

	// Decode and verify MAC (constant-time comparison).
	gotMAC, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return nil, errors.New("malformed token: bad MAC encoding")
	}
	expectedMAC := ts.computeMAC(encodedPayload)
	if !hmac.Equal(gotMAC, expectedMAC) {
		return nil, errors.New("invalid token signature")
	}

	// Decode and unmarshal payload.
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, errors.New("malformed token: bad payload encoding")
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("malformed token: invalid JSON payload: %w", err)
	}
	if claims.V != tokenVersion {
		return nil, fmt.Errorf("unknown token version %d", claims.V)
	}
	return &claims, nil
}

// computeMAC returns HMAC-SHA256(ts.signingKey, []byte(encodedPayload)).
func (ts *TokenStore) computeMAC(encodedPayload string) []byte {
	mac := hmac.New(sha256.New, ts.signingKey)
	mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}

// isRevoked reports whether tokenID is in the revocation list.
func (ts *TokenStore) isRevoked(tokenID string) bool {
	ts.mu.RLock()
	_, ok := ts.revoked[tokenID]
	ts.mu.RUnlock()
	return ok
}

// randomHex returns n cryptographically random bytes encoded as a lowercase
// hex string (length 2*n).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
