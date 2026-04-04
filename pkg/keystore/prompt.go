package keystore

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func promptPassphrase() (string, error) {
	fmt.Fprint(os.Stderr, "AgentKMS key passphrase: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("keystore: read passphrase: %w", err)
	}
	return string(b), nil
}

func promptNewPassphrase() (string, error) {
	fmt.Fprint(os.Stderr, "New AgentKMS key passphrase: ")
	b1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("keystore: read passphrase: %w", err)
	}
	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	b2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("keystore: read passphrase: %w", err)
	}
	if string(b1) != string(b2) {
		return "", fmt.Errorf("keystore: passphrases do not match")
	}
	if len(b1) < 8 {
		return "", fmt.Errorf("keystore: passphrase must be at least 8 characters")
	}
	return string(b1), nil
}
