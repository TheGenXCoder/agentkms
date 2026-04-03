// export_test.go exposes internal symbols for use in tests outside this
// package (specifically internal/api and integration tests).
//
// IMPORTANT: Go's export_test.go mechanism (package foo, _test.go suffix)
// only works for test files within the SAME package directory.  It does NOT
// make symbols available to external packages that import this package during
// their own test builds.  Any symbol that must be accessible cross-package
// (e.g. from internal/api tests) must live in a regular (non-test) production
// file.
//
// InjectTokenForTest is therefore defined in middleware.go, not here.
package auth

import (
	"fmt"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// NewTokenServiceWithClock constructs a TokenService with an injectable clock.
// For testing expiry behaviour without real-time delays.
// Must only be used in tests.
func NewTokenServiceWithClock(revocation *RevocationList, nowFunc func() time.Time) (*TokenService, error) {
	svc, err := NewTokenService(revocation)
	if err != nil {
		return nil, err
	}
	svc.nowFunc = nowFunc
	return svc, nil
}

// IssueWithOverriddenClaimsForTest signs a token with specific JTI, Subject,
// CertFP, and Team values.  Allows testing the required-claims validation path
// (tokens.go verify()) which is unreachable via the normal Issue() API because
// Issue() always produces non-empty required fields.
//
// All other claim fields (role, spiffe, iat, exp) are set to valid defaults.
// The resulting token has a valid HMAC, so it reaches the claims check.
//
// Must only be used in tests.
func (s *TokenService) IssueWithOverriddenClaimsForTest(
	jti, sub, team, cfp string,
	id *identity.Identity,
) (string, error) {
	now := s.nowFunc()
	claims := tokenClaims{
		JTI:       jti,
		Subject:   sub,
		Team:      team,
		Role:      string(identity.RoleDeveloper),
		CertFP:    cfp,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(TokenTTL).Unix(),
	}
	if id != nil {
		claims.SPIFFE = id.SPIFFEID
	}
	tokenStr, err := s.sign(claims)
	if err != nil {
		return "", fmt.Errorf("IssueWithOverriddenClaimsForTest: %w", err)
	}
	return tokenStr, nil
}
