package honeytokens

import (
	"crypto/rand"
	"fmt"
	"sync"
)

// HoneytokenInfo holds the UUID and human-readable name of an active honeytoken.
type HoneytokenInfo struct {
	UUID string
	Name string
}

// Store manages honeytoken lifecycle with an active-count hard cap.
type Store struct {
	mu        sync.Mutex
	maxActive int
	tokens    map[string]string // uuid -> name
}

// NewStore returns a Store that enforces maxActive as the hard cap on
// simultaneously active honeytokens.
func NewStore(maxActive int) *Store {
	return &Store{
		maxActive: maxActive,
		tokens:    make(map[string]string),
	}
}

// Create registers a new honeytoken with the given name.
// It returns the token's UUID or an error if the active cap has been reached.
func (s *Store) Create(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.tokens) >= s.maxActive {
		return "", fmt.Errorf("active honeytoken cap reached (limit: %d)", s.maxActive)
	}

	uuid, err := generateUUID()
	if err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}

	s.tokens[uuid] = name
	return uuid, nil
}

// Revoke deactivates the honeytoken identified by uuid, freeing a slot.
func (s *Store) Revoke(uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tokens[uuid]; !ok {
		return fmt.Errorf("honeytoken %q not found", uuid)
	}
	delete(s.tokens, uuid)
	return nil
}

// Active returns the number of currently active honeytokens.
func (s *Store) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// List returns info for every active honeytoken.
func (s *Store) List() []HoneytokenInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]HoneytokenInfo, 0, len(s.tokens))
	for uuid, name := range s.tokens {
		result = append(result, HoneytokenInfo{UUID: uuid, Name: name})
	}
	return result
}

// generateUUID produces a version-4 UUID string.
func generateUUID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}
