package githubapp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/agentkms/agentkms/internal/credentials"
)

const (
	kvPrefix = "github-apps/"

	kvFieldAppID          = "app_id"
	kvFieldInstallationID = "installation_id"
	kvFieldPrivateKeyPEM  = "private_key_pem"
)

// KVStore is the production Store implementation backed by credentials.KVWriter.
// The KV layer (EncryptedKV or OpenBaoKV) encrypts all stored fields at rest.
type KVStore struct {
	kv credentials.KVWriter
}

// NewKVStore returns a KVStore backed by kv.
func NewKVStore(kv credentials.KVWriter) *KVStore {
	return &KVStore{kv: kv}
}

func kvPath(name string) string {
	return kvPrefix + name
}

// Save creates or replaces the App registration at github-apps/<name>.
func (s *KVStore) Save(ctx context.Context, app GithubApp) error {
	fields := map[string]string{
		kvFieldAppID:         strconv.FormatInt(app.AppID, 10),
		kvFieldInstallationID: strconv.FormatInt(app.InstallationID, 10),
		kvFieldPrivateKeyPEM:  string(app.PrivateKeyPEM),
	}
	if err := s.kv.SetSecret(ctx, kvPath(app.Name), fields); err != nil {
		return fmt.Errorf("githubapp: save %q: %w", app.Name, err)
	}
	return nil
}

// Get retrieves the full App (including private key) by name.
func (s *KVStore) Get(ctx context.Context, name string) (*GithubApp, error) {
	fields, err := s.kv.GetSecret(ctx, kvPath(name))
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("githubapp: get %q: %w", name, err)
	}

	appID, err := strconv.ParseInt(fields[kvFieldAppID], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("githubapp: corrupt app_id for %q: %w", name, err)
	}
	installationID, err := strconv.ParseInt(fields[kvFieldInstallationID], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("githubapp: corrupt installation_id for %q: %w", name, err)
	}

	return &GithubApp{
		Name:           name,
		AppID:          appID,
		InstallationID: installationID,
		PrivateKeyPEM:  []byte(fields[kvFieldPrivateKeyPEM]),
	}, nil
}

// List returns summaries of all registered Apps (no private key bytes).
func (s *KVStore) List(ctx context.Context) ([]Summary, error) {
	paths, err := s.kv.ListPaths(ctx)
	if err != nil {
		return nil, fmt.Errorf("githubapp: list paths: %w", err)
	}

	var out []Summary
	for _, path := range paths {
		if !strings.HasPrefix(path, kvPrefix) {
			continue
		}
		name := strings.TrimPrefix(path, kvPrefix)
		if name == "" {
			continue
		}

		fields, err := s.kv.GetSecret(ctx, path)
		if err != nil {
			// Skip inaccessible entries rather than aborting the whole list.
			continue
		}

		appID, _ := strconv.ParseInt(fields[kvFieldAppID], 10, 64)
		installID, _ := strconv.ParseInt(fields[kvFieldInstallationID], 10, 64)
		out = append(out, Summary{
			Name:           name,
			AppID:          appID,
			InstallationID: installID,
		})
	}
	return out, nil
}

// Delete removes the App registration. Idempotent: returns nil if absent.
func (s *KVStore) Delete(ctx context.Context, name string) error {
	if err := s.kv.DeleteSecret(ctx, kvPath(name)); err != nil {
		if isNotFound(err) {
			return nil // idempotent
		}
		return fmt.Errorf("githubapp: delete %q: %w", name, err)
	}
	return nil
}

// isNotFound returns true for KV-layer not-found errors.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such")
}
