package credentials

import (
	"context"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/backend"
)

type mockRotatableBackend struct {
	keys        map[string]*backend.KeyMeta
	listErr     error
	rotateErr   error
	rotatedKeys []string
}

func (m *mockRotatableBackend) RotateKey(ctx context.Context, id string) (*backend.KeyMeta, error) {
	if m.rotateErr != nil {
		return nil, m.rotateErr
	}
	m.rotatedKeys = append(m.rotatedKeys, id)
	return m.keys[id], nil
}

func (m *mockRotatableBackend) ListKeys(ctx context.Context, scope backend.KeyScope) ([]*backend.KeyMeta, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var res []*backend.KeyMeta
	for _, k := range m.keys {
		res = append(res, k)
	}
	return res, nil
}

func TestRotator_checkAndRotate(t *testing.T) {
	ctx := context.Background()

	now := time.Now().UTC()
	oldTime := now.Add(-40 * 24 * time.Hour) // > 30 days
	recentTime := now.Add(-10 * 24 * time.Hour)

	mockBknd := &mockRotatableBackend{
		keys: map[string]*backend.KeyMeta{
			"key-old": {
				KeyID:     "key-old",
				CreatedAt: oldTime,
			},
			"key-recent": {
				KeyID:     "key-recent",
				CreatedAt: oldTime,
				RotatedAt: &recentTime,
			},
		},
	}

	rotator := NewRotator(mockBknd, []string{"key-old", "key-recent", "key-missing"}, 30*24*time.Hour)
	rotator.nowFunc = func() time.Time { return now }

	rotator.checkAndRotate(ctx)

	if len(mockBknd.rotatedKeys) != 1 {
		t.Fatalf("Expected 1 key rotated, got %d", len(mockBknd.rotatedKeys))
	}
	if mockBknd.rotatedKeys[0] != "key-old" {
		t.Errorf("Expected key-old to be rotated, got %s", mockBknd.rotatedKeys[0])
	}
}

func TestRotator_Start(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	mockBknd := &mockRotatableBackend{
		keys: map[string]*backend.KeyMeta{},
	}
	// Interval is 1ms
	rotator := NewRotator(mockBknd, []string{}, time.Millisecond)

	go rotator.Start(ctx)

	time.Sleep(5 * time.Millisecond)
	cancel()
	time.Sleep(2 * time.Millisecond)
}

// TestNewRotator_DefaultNowFunc ensures the constructor installs a usable
// nowFunc closure (other tests override it with mocks, leaving the default
// closure uncovered).
func TestNewRotator_DefaultNowFunc(t *testing.T) {
	r := NewRotator(&mockRotatableBackend{}, []string{"k"}, time.Hour)
	if r.nowFunc == nil {
		t.Fatal("expected nowFunc to be set, got nil")
	}
	// Invoke the closure — it should return a UTC time close to now.
	got := r.nowFunc()
	if got.Location() != time.UTC {
		t.Errorf("expected UTC location, got %s", got.Location())
	}
	if diff := time.Since(got); diff < 0 || diff > time.Second {
		t.Errorf("expected nowFunc to return a time within 1s of now, got diff=%v", diff)
	}
}
