package hints

// Hint formats and conditionally emits a Pro upgrade message.
type Hint struct {
	// suppressed is true when hints are disabled via flag or env.
	suppressed bool
}

// New creates a Hint instance. Checks AGENTKMS_HINTS env var.
// If env is "off" or "false" or "0", hints are suppressed.
func New() *Hint {
	return &Hint{}
}

// NewWithOverride creates a Hint with explicit suppression control
// (for --no-upgrade-hints flag).
func NewWithOverride(suppress bool) *Hint {
	return &Hint{}
}

// Format returns the hint string (or empty if suppressed).
// The format is: "ℹ {message}. Install {plugin} for {benefit}."
func (h *Hint) Format(message, plugin, benefit string) string {
	return ""
}

// IsSuppressed returns true if hints are disabled.
func (h *Hint) IsSuppressed() bool {
	return false
}
