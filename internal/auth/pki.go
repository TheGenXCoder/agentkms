package auth

// PKI engine integration — A-10.
//
// PKIClient issues X.509 client certificates via OpenBao's PKI secrets engine.
// It is the sole mechanism for enrolling a new identity into AgentKMS.
//
// SECURITY INVARIANTS:
//
//  1. The issued private key is NEVER logged, stored in the audit trail, or
//     passed to any function other than the file writer in cmd/enroll.
//     It is treated as key material throughout.
//
//  2. The bootstrap token used to call PKI is short-lived and single-purpose.
//     It is held in memory only for the duration of the enrollment call.
//
//  3. PKIClient does NOT store any keys or tokens — it is stateless.
//
//  4. TLS is enforced when Address uses https:// (system CA pool used for
//     server cert verification). Always use https:// in production.
//     http:// is only permitted for local dev (loopback only).

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrPKIIssueFailed is returned when the PKI engine rejects cert issuance.
var ErrPKIIssueFailed = errors.New("auth: PKI cert issuance failed")

// CertBundle holds the issued certificate and its private key.
//
// SECURITY: PrivateKeyPEM is sensitive material. The caller must:
//   - Write it to a file with mode 0600 immediately
//   - Zero the slice after writing (or let it be GC'd — Go does not zero
//     memory on collection, but the key's lifetime is bounded to enrollment)
//   - Never log, audit, or transmit PrivateKeyPEM
type CertBundle struct {
	// CertificatePEM is the PEM-encoded X.509 certificate (public).
	CertificatePEM string

	// PrivateKeyPEM is the PEM-encoded private key.
	// SECURITY: treat as key material — see struct comment.
	PrivateKeyPEM string

	// CAPEM is the PEM-encoded issuing CA certificate.
	// The client uses this to trust the AgentKMS server's TLS certificate.
	CAPEM string

	// SerialNumber is the certificate's serial number (hex, colon-separated).
	SerialNumber string

	// ExpiresAt is when the certificate expires (UTC).
	ExpiresAt time.Time
}

// PKIConfig holds connection parameters for the OpenBao PKI engine.
type PKIConfig struct {
	// Address is the OpenBao base URL, e.g. "https://openbao.internal:8200".
	Address string

	// BootstrapToken is a Vault token with permission to call
	// /pki/issue/{role}. This is a short-lived, single-purpose token
	// issued by the platform admin as part of the enrollment bootstrap.
	//
	// SECURITY: never log this value.
	BootstrapToken string `json:"-"`

	// TLSConfig is the TLS configuration for the Vault client, including
	// client certificates for mTLS.
	// Required in production.
	TLSConfig *tls.Config

	// PKIMount is the path where the PKI engine is mounted.
	// Defaults to "pki" if empty.
	PKIMount string

	// Role is the PKI role to use for cert issuance.
	// Defaults to "agentkms" if empty.
	Role string
}

// PKIClient issues certificates via OpenBao PKI.
type PKIClient struct {
	cfg    PKIConfig
	client *http.Client
}

// NewPKIClient constructs a PKIClient.
func NewPKIClient(cfg PKIConfig) *PKIClient {
	if cfg.PKIMount == "" {
		cfg.PKIMount = "pki"
	}
	if cfg.Role == "" {
		cfg.Role = "agentkms"
	}
	// Warn if Address uses plain HTTP outside loopback.
	// Bootstrap tokens sent over http:// are visible on the wire.
	addr := strings.ToLower(cfg.Address)
	if strings.HasPrefix(addr, "http://") &&
		!strings.Contains(addr, "127.0.0.1") &&
		!strings.Contains(addr, "localhost") {
		// We deliberately do not panic here — enforcement is the caller's
		// responsibility, but we surface the risk at construction time.
		fmt.Fprintf(os.Stderr,
			"agentkms: WARNING: PKIClient Address uses http:// for a non-loopback host;\n"+
			"  bootstrap tokens will be sent in plaintext.\n"+
			"  Use https:// in production.\n")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = cfg.TLSConfig

	return &PKIClient{
		cfg:    cfg,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// pkiIssueRequest is the request body for /pki/issue/{role}.
type pkiIssueRequest struct {
	CommonName string `json:"common_name"`
	// Organization is mapped to the certificate O field (team ID).
	// OpenBao injects this into the cert if the role permits it.
	Organization []string `json:"organization,omitempty"`
	// OtherSANs can carry a SPIFFE ID: "spiffe://...:UTF8:<value>".
	OtherSANs []string `json:"other_sans,omitempty"`
	TTL       string   `json:"ttl"`
	Format    string   `json:"format"` // "pem"
}

// pkiIssueResponse is the Vault API response envelope for PKI issuance.
type pkiIssueResponse struct {
	Data struct {
		Certificate    string `json:"certificate"`
		IssuingCA      string `json:"issuing_ca"`
		PrivateKey     string `json:"private_key"`
		SerialNumber   string `json:"serial_number"`
		Expiration     int64  `json:"expiration"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// IssueCert requests a new client certificate for the given identity.
//
// callerID becomes the certificate's Common Name (CN).
// teamID becomes the certificate's Organisation (O) field.
// ttl is the requested certificate lifetime (e.g. "720h" = 30 days).
//
// Returns a CertBundle whose PrivateKeyPEM must be treated as key material.
// Returns ErrPKIIssueFailed if the PKI engine rejects the request.
func (p *PKIClient) IssueCert(ctx context.Context, callerID, teamID, spiffeID, ttl string) (*CertBundle, error) {
	if callerID == "" {
		return nil, fmt.Errorf("auth: PKIClient.IssueCert: callerID is required")
	}
	if teamID == "" {
		return nil, fmt.Errorf("auth: PKIClient.IssueCert: teamID is required")
	}
	if ttl == "" {
		ttl = "720h"
	}

	reqBody := pkiIssueRequest{
		CommonName:   callerID,
		Organization: []string{teamID},
		TTL:          ttl,
		Format:       "pem",
	}
	if spiffeID != "" {
		// OpenBao URI SAN format for SPIFFE IDs.
		reqBody.OtherSANs = []string{spiffeID}
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("auth: PKIClient.IssueCert: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/issue/%s",
		strings.TrimRight(p.cfg.Address, "/"),
		strings.Trim(p.cfg.PKIMount, "/"),
		p.cfg.Role,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("auth: PKIClient.IssueCert: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// SECURITY: bootstrap token in header, never in URL.
	req.Header.Set("X-Vault-Token", p.cfg.BootstrapToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: PKIClient.IssueCert: HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("auth: PKIClient.IssueCert: read response: %w", err)
	}

	var result pkiIssueResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("auth: PKIClient.IssueCert: parse response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Include PKI error message (it's a policy/config message, not key material).
		msg := strings.Join(result.Errors, "; ")
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: %s", ErrPKIIssueFailed, msg)
	}

	if result.Data.Certificate == "" || result.Data.PrivateKey == "" {
		return nil, fmt.Errorf("%w: response missing certificate or private_key", ErrPKIIssueFailed)
	}

	expiresAt := time.Unix(result.Data.Expiration, 0).UTC()

	return &CertBundle{
		CertificatePEM: result.Data.Certificate,
		PrivateKeyPEM:  result.Data.PrivateKey, // SECURITY: caller must handle as key material
		CAPEM:          result.Data.IssuingCA,
		SerialNumber:   result.Data.SerialNumber,
		ExpiresAt:      expiresAt,
	}, nil
}

// FetchCACert retrieves the current CA certificate from the PKI engine.
// Used to bootstrap trust when the client does not yet have the CA cert.
func (p *PKIClient) FetchCACert(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/v1/%s/cert/ca",
		strings.TrimRight(p.cfg.Address, "/"),
		strings.Trim(p.cfg.PKIMount, "/"),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("auth: PKIClient.FetchCACert: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.cfg.BootstrapToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth: PKIClient.FetchCACert: HTTP: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth: PKIClient.FetchCACert: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("auth: PKIClient.FetchCACert: parse: %w", err)
	}
	return result.Data.Certificate, nil
}
