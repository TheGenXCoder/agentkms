package credentials

import (
	"context"
	"log/slog"
	"time"

	"github.com/agentkms/agentkms/internal/backend"
)

// MasterKeyRotationInterval is how often the master LLM keys are rotated.
// Per backlog LV-05: master LLM keys rotate on schedule.
const MasterKeyRotationInterval = 30 * 24 * time.Hour // 30 days

// RotatableBackend is the interface for keys that can be rotated.
// This is typically the Backend interface from internal/backend.
type RotatableBackend interface {
	RotateKey(ctx context.Context, id string) (*backend.KeyMeta, error)
	ListKeys(ctx context.Context, scope backend.KeyScope) ([]*backend.KeyMeta, error)
}

// Rotator handles the scheduled rotation of master keys in the backend.
type Rotator struct {
	bknd     RotatableBackend
	keys     []string
	interval time.Duration
	nowFunc  func() time.Time
}

// NewRotator constructs a Rotator.
func NewRotator(bknd RotatableBackend, keys []string, interval time.Duration) *Rotator {
	return &Rotator{
		bknd:     bknd,
		keys:     keys,
		interval: interval,
		nowFunc:  func() time.Time { return time.Now().UTC() },
	}
}

// Start runs the rotation loop in a background goroutine.
func (r *Rotator) Start(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Initial rotation check on start.
	r.checkAndRotate(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.checkAndRotate(ctx)
		}
	}
}

func (r *Rotator) checkAndRotate(ctx context.Context) {
	// Fetch all keys to check their last rotation time.
	// We use an empty scope to get all keys, then filter by r.keys.
	// This is more efficient than calling GetKeyMeta for each key if there are many,
	// but the Backend interface doesn't have GetKeyMeta.
	allMeta, err := r.bknd.ListKeys(ctx, backend.KeyScope{})
	if err != nil {
		slog.Error("failed to list keys for rotation check", "error", err)
		return
	}

	metaMap := make(map[string]*backend.KeyMeta)
	for _, m := range allMeta {
		metaMap[m.KeyID] = m
	}

	for _, keyID := range r.keys {
		meta, ok := metaMap[keyID]
		if !ok {
			slog.Warn("master key not found in backend, skipping rotation", "key_id", keyID)
			continue
		}

		last := meta.CreatedAt
		if meta.RotatedAt != nil {
			last = *meta.RotatedAt
		}

		if r.nowFunc().Sub(last) >= r.interval {
			slog.Info("rotating master key", "key_id", keyID, "last_rotated", last)
			if _, err := r.bknd.RotateKey(ctx, keyID); err != nil {
				slog.Error("failed to rotate master key", "key_id", keyID, "error", err)
				continue
			}
			slog.Info("successfully rotated master key", "key_id", keyID)
		}
	}
}
