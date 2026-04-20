package honeytokens

// HoneytokenInfo holds the UUID and human-readable name of an active honeytoken.
type HoneytokenInfo struct {
	UUID string
	Name string
}

// Store manages honeytoken lifecycle with an active-count hard cap.
type Store struct{}

// NewStore returns a Store that enforces maxActive as the hard cap on
// simultaneously active honeytokens.
func NewStore(maxActive int) *Store {
	return &Store{}
}

// Create registers a new honeytoken with the given name.
// It returns the token's UUID or an error if the active cap has been reached.
func (s *Store) Create(name string) (string, error) {
	return "", nil
}

// Revoke deactivates the honeytoken identified by uuid, freeing a slot.
func (s *Store) Revoke(uuid string) error {
	return nil
}

// Active returns the number of currently active honeytokens.
func (s *Store) Active() int {
	return 0
}

// List returns info for every active honeytoken.
func (s *Store) List() []HoneytokenInfo {
	return nil
}
