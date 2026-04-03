package auth

import (
	"context"
	"testing"
)

func TestInjectTokenForTest(t *testing.T) {
	ctx := context.Background()

	// Initially nil
	if tok := TokenFromContext(ctx); tok != nil {
		t.Fatalf("Expected nil token, got %v", tok)
	}

	// Inject and retrieve
	expectedTok := &Token{JTI: "test-id"}
	ctx = InjectTokenForTest(ctx, expectedTok)

	tok := TokenFromContext(ctx)
	if tok == nil {
		t.Fatal("Expected non-nil token")
	}
	if tok.JTI != expectedTok.JTI {
		t.Errorf("Expected token JTI %q, got %q", expectedTok.JTI, tok.JTI)
	}
}
