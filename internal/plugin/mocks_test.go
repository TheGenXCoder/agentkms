package plugin

// mocks_test.go — shared test doubles for the plugin package tests.
// These types are available to all *_test.go files in the plugin package.

import (
	"context"

	"github.com/agentkms/agentkms/internal/destination"
)

// mockDestinationDeliverer is a test double for destination.DestinationDeliverer.
type mockDestinationDeliverer struct {
	kind           string
	validateErr    error
	deliverPerm    bool
	deliverErr     error
	revokeErr      error
	healthErr      error
	deliveryCount  int
	revocationCount int
}

func (m *mockDestinationDeliverer) Kind() string { return m.kind }

func (m *mockDestinationDeliverer) Validate(_ context.Context, _ map[string]any) error {
	return m.validateErr
}

func (m *mockDestinationDeliverer) Deliver(_ context.Context, _ destination.DeliverRequest) (bool, error) {
	m.deliveryCount++
	return m.deliverPerm, m.deliverErr
}

func (m *mockDestinationDeliverer) Revoke(_ context.Context, _ string, _ uint64, _ map[string]any) (bool, error) {
	m.revocationCount++
	return false, m.revokeErr
}

func (m *mockDestinationDeliverer) Health(_ context.Context) error {
	return m.healthErr
}
