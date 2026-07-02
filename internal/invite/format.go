// Package invite implements the kpmi1 invite code format (UX consolidation D1/D3).
package invite

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const prefix = "kpmi1_"

// Payload is the decoded invite code content.
type Payload struct {
	Version       int    `json:"v"`
	ServerURL     string `json:"url"`
	CAFingerprint string `json:"ca_fp"`
	Token         string `json:"token"`
	UserID        string `json:"user,omitempty"`
	Tenant        string `json:"tenant,omitempty"`
	ExpiresAt     int64  `json:"exp"` // Unix seconds
}

// Encode builds a kpmi1_<base64url(json)> invite code.
func Encode(p Payload) (string, error) {
	if p.Version == 0 {
		p.Version = 1
	}
	if p.ServerURL == "" || p.CAFingerprint == "" || p.Token == "" {
		return "", fmt.Errorf("invite: url, ca_fp, and token are required")
	}
	if p.ExpiresAt == 0 {
		return "", fmt.Errorf("invite: exp is required")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("invite: marshal: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode parses a kpmi1 invite code.
func Decode(code string) (Payload, error) {
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, prefix) {
		return Payload{}, fmt.Errorf("invite: expected %q prefix", prefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, prefix))
	if err != nil {
		return Payload{}, fmt.Errorf("invite: decode base64: %w", err)
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Payload{}, fmt.Errorf("invite: parse json: %w", err)
	}
	if p.Version != 1 {
		return Payload{}, fmt.Errorf("invite: unsupported version %d", p.Version)
	}
	if p.ServerURL == "" || p.CAFingerprint == "" || p.Token == "" {
		return Payload{}, fmt.Errorf("invite: missing required fields")
	}
	if p.ExpiresAt > 0 && time.Now().UTC().After(time.Unix(p.ExpiresAt, 0)) {
		return Payload{}, fmt.Errorf("invite: code expired")
	}
	return p, nil
}
