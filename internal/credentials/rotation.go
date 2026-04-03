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
}

// Rotator handles the scheduled rotation of master keys in the backend.
type Rotator struct {
	bknd       RotatableBackend
	keys       []string
	interval   time.Duration
	nowFunc    func() time.Time
	lastRotate map[string]time.Time
}

// NewRotator constructs a Rotator.
func NewRotator(bknd RotatableBackend, keys []string, interval time.Duration) *Rotator {
	return &Rotator{
		bknd:       bknd,
		keys:       keys,
		interval:   interval,
		nowFunc:    func() time.Time { return time.Now().UTC() },
		lastRotate: make(map[string]time.Time),
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
	for _, keyID := range r.keys {
		last, ok := r.lastRotate[keyID]
		if !ok || r.nowFunc().Sub(last) >= r.interval {
			slog.Info("rotating master key", "key_id", keyID)
			if _, err := r.bknd.RotateKey(ctx, keyID); err != nil {
				slog.Error("failed to rotate master key", "key_id", keyID, "error", err)
				continue
			}
			r.lastRotate[keyID] = r.nowFunc()
			slog.Info("successfully rotated master key", "key_id", keyID)
		}
	}
}
