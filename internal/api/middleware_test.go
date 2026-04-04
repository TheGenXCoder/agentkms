package api_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

func TestAuthMiddleware(t *testing.T) {
	rl := auth.NewRevocationList()
	svc, err := auth.NewTokenService(rl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	b := backend.NewDevBackend()
	a := &nullAuditor{}
	p := policy.New(policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				ID:     "allow-all",
				Effect: policy.EffectAllow,
				Match:  policy.Match{},
			},
		},
	})

	server := api.NewServer(b, a, policy.AsEngineI(p), svc, "test")
	cert := makeTestCert(t, "bert@platform-team")

	handler := api.NewAuthHandler(svc, a, policy.AsEngineI(p), "test")
	tokenStr := sessionToken(t, handler, cert.Cert)

	tests := []struct {
		name           string
		setupReq       func(*http.Request)
		expectedStatus int
	}{
		{
			name: "valid token and matching mTLS",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+tokenStr)
				r.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert.Cert},
				}
			},
			expectedStatus: http.StatusOK, // /keys returns 200 for valid token (or empty list)
		},
		{
			name: "missing Authorization header",
			setupReq: func(r *http.Request) {
				r.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert.Cert},
				}
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer invalid-token")
				r.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert.Cert},
				}
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "missing mTLS connection",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+tokenStr)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "mTLS cert mismatch",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+tokenStr)
				otherCert := makeTestCert(t, "other@platform-team")
				r.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{otherCert.Cert},
				}
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/keys", nil)
			tt.setupReq(r)
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
