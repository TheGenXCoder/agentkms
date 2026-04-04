package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// TokenTTL is the lifetime of a newly issued session token.
// Per architecture §7.4: 15 minutes maximum.
const TokenTTL = 15 * time.Minute

// ErrTokenInvalid is returned by Validate when a token has an invalid
// signature, malformed structure, or has expired.
var ErrTokenInvalid = errors.New("auth: token invalid")

// ErrTokenRevoked is returned by Validate when the token's JTI is present
// in the revocation list.
var ErrTokenRevoked = errors.New("auth: token revoked")

// ── Token format ─────────────────────────────────────────────────────────────
//
// Format: <base64url(json-claims)>.<base64url(hmac-sha256)>
//
// The HMAC is computed over the raw base64url-encoded claims string.  This is
// intentionally simpler than JWT (no header, no algorithm negotiation) because
// we support exactly one algorithm: HMAC-SHA256 with a server-managed key.
//
// The claims JSON uses short field names to keep tokens compact.  No sensitive
// data (key material, plaintext) is ever stored in the token.

// tokenClaims is the JSON payload embedded in a session token.
// Field names are intentionally short (no sensitive data; just compact).
type tokenClaims struct {
	JTI       string   `json:"jti"`            // Unique token ID (used for revocation)
	Subject   string   `json:"sub"`            // CallerID from cert CN
	Team      string   `json:"team"`           // TeamID from cert O
	Role      string   `json:"role"`           // Role from cert OU
	SPIFFE    string   `json:"spiffe,omitempty"` // SPIFFE ID from cert SAN (may be empty)
	CertFP    string   `json:"cfp"`            // Cert fingerprint (SHA-256 hex of DER)
	Scopes    []string `json:"scp,omitempty"`   // Delegated scopes
	IssuedAt  int64    `json:"iat"`            // Unix timestamp (seconds)
	ExpiresAt int64    `json:"exp"`            // Unix timestamp (seconds)
}

// Token is a validated, parsed session token.  Returned by TokenService.Validate
// and TokenService.Revoke for use in handlers and audit logging.
type Token struct {
	// JTI is the unique token identifier.  Used as the AgentSession identifier
	// in audit events to correlate all operations in a session.
	JTI string

	// Identity holds the caller identity bound to this token.
	Identity identity.Identity

	// IssuedAt is when the token was issued (UTC).
	IssuedAt time.Time

	// ExpiresAt is when the token expires (UTC).
	ExpiresAt time.Time
}

// ── TokenService ──────────────────────────────────────────────────────────────

// TokenService manages session token issuance, validation, and revocation.
//
// The HMAC signing key is generated once at construction from crypto/rand
// and is never exposed through any method.  All token operations go through
// this service.
//
// Concurrency: safe for concurrent use.
//
// A-03, A-04, A-05.
type TokenService struct {
	// signingKey is the HMAC-SHA256 key for token signing and verification.
	// SECURITY: unexported; never included in logs, errors, or return values.
	signingKey []byte

	// revocation is the revocation blocklist.  Revoked JTIs are rejected by
	// Validate even if the token signature and TTL are valid.
	revocation *RevocationList

	// nowFunc returns the current time in UTC.  Defaults to time.Now().UTC.
	// Injectable for testing to allow deterministic expiry verification
	// without real-time delays.
	nowFunc func() time.Time
}

// NewTokenService creates a TokenService with a randomly generated 256-bit
// HMAC signing key.
//
// The key is generated from crypto/rand and is never exposed.  It is
// ephemeral for Tier 0 (in-memory dev mode); Tier 1+ should persist it in
// the backend or use a KMS-backed signing key.
func NewTokenService(revocation *RevocationList) (*TokenService, error) {
	key := make([]byte, 32) // 256-bit HMAC-SHA256 key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// SECURITY: if we cannot get entropy, fail hard. We must not issue
		// tokens with a predictable or empty key.
		return nil, fmt.Errorf("auth: generating token signing key: %w", err)
	}
	return &TokenService{
		signingKey: key,
		revocation: revocation,
		nowFunc:    func() time.Time { return time.Now().UTC() },
	}, nil
}

// Issue creates and signs a new session token for the given identity.
//
// The token encodes the identity fields and a cert fingerprint so that
// RequireToken middleware can verify the token is being used on the same
// mTLS connection that authenticated it.
//
// TTL is TokenTTL (15 minutes) from time of issuance.
func (s *TokenService) Issue(id *identity.Identity) (string, *Token, error) {
	jti, err := newJTI()
	if err != nil {
		return "", nil, fmt.Errorf("auth: generating token ID: %w", err)
	}

	now := s.nowFunc()
	exp := now.Add(TokenTTL)

	claims := tokenClaims{
		JTI:       jti,
		Subject:   id.CallerID,
		Team:      id.TeamID,
		Role:      string(id.Role),
		SPIFFE:    id.SPIFFEID,
		CertFP:    id.CertFingerprint,
		Scopes:    id.Scopes,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
	}

	tokenStr, err := s.sign(claims)
	if err != nil {
		return "", nil, err
	}

	tok := &Token{
		JTI:       jti,
		Identity:  *id,
		IssuedAt:  now,
		ExpiresAt: exp,
	}
	return tokenStr, tok, nil
}

// Validate parses and fully verifies a token string.
//
// Verification steps (all must pass):
//  1. Token structure is well-formed (two base64url segments separated by ".")
//  2. HMAC-SHA256 signature matches (constant-time comparison)
//  3. Required claims are present (jti, sub, cfp)
//  4. Token has not expired (exp > now)
//  5. JTI is not in the revocation list
//
// Returns ErrTokenInvalid for structural, signature, or expiry failures.
// Returns ErrTokenRevoked when the JTI has been explicitly revoked.
//
// SECURITY: error messages intentionally do not distinguish between "bad
// signature" and "expired" to avoid oracle attacks.
func (s *TokenService) Validate(tokenStr string) (*Token, error) {
	claims, err := s.verify(tokenStr)
	if err != nil {
		return nil, err
	}

	// Check expiry before revocation to fail fast on the cheapest check.
	now := s.nowFunc()
	exp := time.Unix(claims.ExpiresAt, 0).UTC()
	if now.After(exp) {
		return nil, fmt.Errorf("%w: token expired", ErrTokenInvalid)
	}

	// Check revocation blocklist.
	if s.revocation.IsRevoked(claims.JTI) {
		return nil, ErrTokenRevoked
	}

	return claimsToToken(claims), nil
}

// Revoke adds the token's JTI to the revocation blocklist.
//
// Revoke verifies the token signature before revoking; tokens with invalid
// signatures are rejected to prevent arbitrary JTI pollution of the blocklist.
// Expiry is NOT checked — a token that is valid but about to expire can still
// be explicitly revoked (session shutdown use case).
//
// Returns the parsed Token for audit logging.  Returns ErrTokenInvalid if
// the signature is invalid.  Revoking an already-revoked token is a no-op.
func (s *TokenService) Revoke(tokenStr string) (*Token, error) {
	claims, err := s.verify(tokenStr)
	if err != nil {
		return nil, err
	}

	exp := time.Unix(claims.ExpiresAt, 0).UTC()
	s.revocation.Revoke(claims.JTI, exp)

	return claimsToToken(claims), nil
}

// ── Token format implementation ───────────────────────────────────────────────

// sign serialises claims as JSON, base64url-encodes them, computes an
// HMAC-SHA256 over the encoded payload, and returns "payload.mac".
func (s *TokenService) sign(claims tokenClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: marshalling token claims: %w", err)
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := computeHMAC(s.signingKey, encodedPayload)
	encodedMAC := base64.RawURLEncoding.EncodeToString(mac)

	return encodedPayload + "." + encodedMAC, nil
}

// verify splits and validates the "payload.mac" format of a token string.
// It does NOT check expiry or revocation — callers must do that after verify.
//
// Returns ErrTokenInvalid (wrapped) on any structural or HMAC failure.
func (s *TokenService) verify(tokenStr string) (*tokenClaims, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("%w: empty token string", ErrTokenInvalid)
	}

	// Split on the last "." to separate payload from MAC.
	// base64url uses A-Z a-z 0-9 - _ (no dots), so any "." is our separator.
	// We split on the LAST dot so that any future payload format changes
	// (e.g. additional dots) remain backward compatible.
	idx := strings.LastIndexByte(tokenStr, '.')
	if idx < 0 {
		return nil, fmt.Errorf("%w: missing MAC separator", ErrTokenInvalid)
	}

	encodedPayload := tokenStr[:idx]
	encodedMAC := tokenStr[idx+1:]

	if encodedPayload == "" || encodedMAC == "" {
		return nil, fmt.Errorf("%w: empty payload or MAC segment", ErrTokenInvalid)
	}

	// Decode and verify MAC before touching payload bytes (fail fast).
	mac, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return nil, fmt.Errorf("%w: MAC decode error", ErrTokenInvalid)
	}

	expected := computeHMAC(s.signingKey, encodedPayload)
	// hmac.Equal is constant-time to prevent timing oracle attacks.
	if !hmac.Equal(mac, expected) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrTokenInvalid)
	}

	// Decode payload only after MAC verification.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload decode error", ErrTokenInvalid)
	}

	var claims tokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload unmarshal error", ErrTokenInvalid)
	}

	// Required claims: all four must be non-empty in every legitimate token.
	// Team is always set from cert.O (identity extraction rejects empty O),
	// so an empty Team claim indicates a forged or corrupted token.
	if claims.JTI == "" || claims.Subject == "" || claims.CertFP == "" || claims.Team == "" {
		return nil, fmt.Errorf("%w: missing required claims (jti/sub/cfp/team)", ErrTokenInvalid)
	}

	return &claims, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// computeHMAC computes HMAC-SHA256 of data using key.
// This is the only place in this package that touches the signing key.
func computeHMAC(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// IssueDelegated creates and signs a new session token with a specific
// TTL and scopes.  Used for sub-agent delegation (FX-02).
//
// The new token is bound to the same identity as the parent, but with
// a restricted set of scopes and a typically shorter TTL.
func (s *TokenService) IssueDelegated(id *identity.Identity, ttl time.Duration, scopes []string) (string, *Token, error) {
	jti, err := newJTI()
	if err != nil {
		return "", nil, fmt.Errorf("auth: generating token ID: %w", err)
	}

	now := s.nowFunc()
	exp := now.Add(ttl)

	claims := tokenClaims{
		JTI:       jti,
		Subject:   id.CallerID,
		Team:      id.TeamID,
		Role:      string(id.Role),
		SPIFFE:    id.SPIFFEID,
		CertFP:    id.CertFingerprint,
		Scopes:    scopes,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
	}

	tokenStr, err := s.sign(claims)
	if err != nil {
		return "", nil, err
	}

	idWithScopes := *id
	idWithScopes.Scopes = scopes

	tok := &Token{
		JTI:       jti,
		Identity:  idWithScopes,
		IssuedAt:  now,
		ExpiresAt: exp,
	}
	return tokenStr, tok, nil
}

// claimsToToken converts validated tokenClaims to a Token.
// IssueBootstrapToken issues a short-lived, single-use bootstrap token
// for use during device recovery re-enrollment.
func (s *TokenService) IssueBootstrapToken(callerID string) (string, error) {
	id := &identity.Identity{
		CallerID: callerID,
		Role:     identity.RoleDeveloper,
	}
	tokenStr, _, err := s.IssueDelegated(id, RecoveryTokenTTL, []string{"enroll:self"})
	if err != nil {
		return "", fmt.Errorf("auth: issue bootstrap token: %w", err)
	}
	return tokenStr, nil
}

func claimsToToken(claims *tokenClaims) *Token {
	return &Token{
		JTI: claims.JTI,
		Identity: identity.Identity{
			CallerID:        claims.Subject,
			TeamID:          claims.Team,
			Role:            identity.Role(claims.Role),
			SPIFFEID:        claims.SPIFFE,
			CertFingerprint: claims.CertFP,
			Scopes:          claims.Scopes,
		},
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}
}

// newJTI generates a UUID v4 token ID using crypto/rand.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("auth: reading random bytes for JTI: %w", err)
	}
	// Set RFC 4122 version (4) and variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
