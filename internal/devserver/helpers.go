package devserver

import (
	"fmt"
	"os"
	"path/filepath"
)

func resolveDir(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("AGENTKMS_DIR"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory (use --dir or AGENTKMS_DIR): %w", err)
	}
	return filepath.Join(home, ".agentkms", "dev"), nil
}

func envOrDev(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
