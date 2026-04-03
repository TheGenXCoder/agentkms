package credentials

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenBaoKV implements KVReader against an OpenBao/Vault KV v2 engine.
//
// It calls the Vault HTTP API directly using only the Go standard library —
// no external dependencies.
type OpenBaoKV struct {
	address    string
	token      string
	httpClient *http.Client
}

// NewOpenBaoKV constructs an OpenBaoKV reader.
// address is the OpenBao base URL (e.g. "http://openbao:8200").
// token is the Vault token with read access to the KV mount.
func NewOpenBaoKV(address, token string, tlsConfig *tls.Config) *OpenBaoKV {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &OpenBaoKV{
		address: strings.TrimRight(address, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
	}
}

// kvv2Response is the Vault KV v2 GET response envelope.
type kvv2Response struct {
	Data struct {
		Data map[string]string `json:"data"`
	} `json:"data"`
}

// GetSecret retrieves a KV v2 secret by its full API path.
// path must be the data path: "{mount}/data/{key}" (not "{mount}/{key}").
func (k *OpenBaoKV) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	url := fmt.Sprintf("%s/v1/%s", k.address, strings.TrimPrefix(path, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("credentials: building KV request: %w", err)
	}
	// SECURITY: the token is passed in a header, not a query param or URL.
	req.Header.Set("X-Vault-Token", k.token)
	req.Header.Set("Accept", "application/json")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credentials: KV request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("credentials: reading KV response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: path %q not found in KV", ErrCredentialNotFound, path)
	}
	if resp.StatusCode != http.StatusOK {
		// Do not include the response body — it may contain token info.
		return nil, fmt.Errorf("credentials: KV returned HTTP %d for path %q", resp.StatusCode, path)
	}

	var kv kvv2Response
	if err := json.Unmarshal(body, &kv); err != nil {
		return nil, fmt.Errorf("credentials: parsing KV response: %w", err)
	}
	if kv.Data.Data == nil {
		return nil, fmt.Errorf("%w: %q (KV data envelope is empty)", ErrCredentialNotFound, path)
	}
	return kv.Data.Data, nil
}
