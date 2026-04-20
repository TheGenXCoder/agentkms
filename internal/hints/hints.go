package hints

import (
	"fmt"
	"os"
)

// Hint formats and conditionally emits a Pro upgrade message.
type Hint struct {
	// suppressed is true when hints are disabled via flag or env.
	suppressed bool
}

// New creates a Hint instance. Checks AGENTKMS_HINTS env var.
// If env is "off" or "false" or "0", hints are suppressed.
func New() *Hint {
	v := os.Getenv("AGENTKMS_HINTS")
	suppress := v == "off" || v == "false" || v == "0"
	return &Hint{suppressed: suppress}
}

// NewWithOverride creates a Hint with explicit suppression control
// (for --no-upgrade-hints flag).
func NewWithOverride(suppress bool) *Hint {
	return &Hint{suppressed: suppress}
}

// Format returns the hint string (or empty if suppressed).
// The format is: "ℹ {message}. Install {plugin} for {benefit}."
func (h *Hint) Format(message, plugin, benefit string) string {
	if h.suppressed {
		return ""
	}
	return fmt.Sprintf("ℹ %s. Install %s for %s.", message, plugin, benefit)
}

// IsSuppressed returns true if hints are disabled.
func (h *Hint) IsSuppressed() bool {
	return h.suppressed
}
