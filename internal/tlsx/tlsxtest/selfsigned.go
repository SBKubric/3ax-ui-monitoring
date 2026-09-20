// Package tlsxtest provides the one thing every test that needs a real
// HTTPS listener needs: a throwaway, self-signed certificate on disk. It
// lives under internal/tlsx because tlsx.Build's own "files" mode is the
// first consumer, but it takes no dependency on tlsx itself so step 10's e2e
// setup (and any other package that needs to stand up a TLS listener in a
// test) can import it too.
package tlsxtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WriteSelfSigned generates a fresh ECDSA P-256 key and a self-signed
// certificate valid for "localhost" and 127.0.0.1/::1, writes them as
// cert.pem and key.pem under dir, and returns their paths. It is deliberately
// not a fixture checked into the repo: a certificate generated fresh per test
// run can never go stale or leak a key anyone might mistake for real.
func WriteSelfSigned(t testing.TB, dir string) (cert, key string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlsxtest: generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("tlsxtest: generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mon-server test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("tlsxtest: create certificate: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("tlsxtest: marshal key: %v", err)
	}

	cert = filepath.Join(dir, "cert.pem")
	key = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("tlsxtest: write cert: %v", err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("tlsxtest: write key: %v", err)
	}

	return cert, key
}
