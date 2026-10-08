//nolint:goconst,lll // Public certificate fixtures use explicit test origins and PEM variants.
package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExplicitIssuerRootsKeepVerificationAndReplaceDefaults(t *testing.T) {
	p := newAuthority(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.server.Certificate().Raw})
	if e := os.WriteFile(path, certificate, 0o600); e != nil {
		t.Fatal(e)
	}
	cfg := config{Issuer: p.server.URL, IssuerCAFile: path, ClientID: "client", ProjectID: testProject, Origin: "https://app.test", Callback: "https://app.test/callback"}
	client, e := newOIDC(context.Background(), cfg, "synthetic-secret", nil, time.Now)
	if e != nil {
		t.Fatal("explicit public issuer roots did not connect", e)
	}
	bounded, ok := client.http.Transport.(boundedTransport)
	if !ok {
		t.Fatal("missing bounded transport")
	}
	transport, ok := bounded.base.(*http.Transport)
	if !ok {
		t.Fatal("unexpected production transport")
	}
	if transport.Proxy != nil || transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("explicit roots weakened the client")
	}
	before := p.requests.Load()
	bad := cfg
	bad.Issuer = strings.Replace(p.server.URL, "127.0.0.1", "localhost", 1)
	if _, e = newOIDC(context.Background(), bad, "synthetic-secret", nil, time.Now); e == nil || p.requests.Load() != before {
		t.Fatal("hostname mismatch reached HTTP")
	}
	other := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	wrong, e := x509.CreateCertificate(rand.Reader, other, other, &p.key.PublicKey, p.key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrong}), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e = newOIDC(context.Background(), cfg, "synthetic-secret", nil, time.Now); e == nil || p.requests.Load() != before {
		t.Fatal("untrusted issuer reached HTTP")
	}
}

func TestIssuerRootsRejectNonPublicOrUnboundedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roots")
	for _, data := range [][]byte{nil, []byte("not PEM"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic")}), bytes.Repeat([]byte("x"), maxIssuerRoots+1)} {
		if e := os.WriteFile(path, data, 0o600); e != nil {
			t.Fatal(e)
		}
		if _, e := readIssuerRoots(path); e == nil {
			t.Fatal("invalid root file accepted")
		}
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readIssuerRoots(link); e == nil {
		t.Fatal("symlink root accepted")
	}
	if _, e := readIssuerRoots(dir); e == nil {
		t.Fatal("directory root accepted")
	}
}
