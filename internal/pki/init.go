// Package pki provides local PKI bootstrap for dev and bare-metal prod AgentKMS.
package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// Layout holds paths written by InitDev or InitProd.
type Layout struct {
	Dir        string
	CACertPath string
	CAKeyPath  string
	ServerCert string
	ServerKey  string
}

// Fingerprint returns SHA-256 of the CA cert DER as lowercase hex (64 chars).
func Fingerprint(caCertPath string) (string, error) {
	pemBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("pki: no PEM in %s", caCertPath)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// InitDev generates loopback-only PKI under dir (~/.agentkms/dev).
func InitDev(dir string, force bool) (*Layout, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, ".agentkms", "dev")
	}
	if !force {
		if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err == nil {
			return nil, fmt.Errorf("PKI already exists in %s (use --force to overwrite)", dir)
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	ca, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "agentkms-dev-ca",
		Org:      "AgentKMS Dev",
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}
	server, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           "agentkms-dev",
		Org:          "AgentKMS Dev",
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Validity:     365 * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}

	layout := &Layout{Dir: dir}
	if err := layout.writeBundle(ca, server); err != nil {
		return nil, err
	}
	return layout, nil
}

// InitProd generates hostname-bound PKI under dir (~/.agentkms/prod/<host>).
func InitProd(dir, host string, force bool) (*Layout, error) {
	host = trimHost(host)
	if host == "" {
		return nil, fmt.Errorf("pki: host is required")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, ".agentkms", "prod", host)
	}
	if !force {
		if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err == nil {
			return nil, fmt.Errorf("PKI already exists in %s (use --force to overwrite)", dir)
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	ca, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "agentkms-ca",
		Org:      "AgentKMS",
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}
	server, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           host,
		Org:          "AgentKMS",
		DNSNames:     []string{host},
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Validity:     365 * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}

	layout := &Layout{Dir: dir}
	if err := layout.writeBundle(ca, server); err != nil {
		return nil, err
	}
	return layout, nil
}

func (l *Layout) writeBundle(ca, server *tlsutil.CertBundle) error {
	l.CACertPath = filepath.Join(l.Dir, "ca.crt")
	l.CAKeyPath = filepath.Join(l.Dir, "ca.key")
	l.ServerCert = filepath.Join(l.Dir, "server.crt")
	l.ServerKey = filepath.Join(l.Dir, "server.key")

	if err := writePEM(l.CACertPath, ca.CertPEM, 0644); err != nil {
		return err
	}
	if err := writePEM(l.CAKeyPath, ca.KeyPEM, 0600); err != nil {
		return err
	}
	if err := writePEM(l.ServerCert, server.CertPEM, 0644); err != nil {
		return err
	}
	return writePEM(l.ServerKey, server.KeyPEM, 0600)
}

func writePEM(path string, pemBytes []byte, mode os.FileMode) error {
	return os.WriteFile(path, pemBytes, mode)
}

func trimHost(host string) string {
	host = filepath.ToSlash(host) // noop for URLs but safe
	for _, p := range []string{"https://", "http://"} {
		if len(host) > len(p) && host[:len(p)] == p {
			host = host[len(p):]
		}
	}
	if i := len(host); i > 0 {
		for j, c := range host {
			if c == '/' || c == ':' {
				// keep port if present — caller passes FQDN only per design
				if c == ':' {
					return host[:j] + host[j:]
				}
				return host[:j]
			}
		}
	}
	return host
}
