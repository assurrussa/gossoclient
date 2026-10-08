//nolint:goconst,lll // Explicit wire literals and fixture cases stay readable at each assertion.
package browser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if e := os.WriteFile(path, []byte("secret"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e := readProtected(path, 10); e != nil {
		t.Fatal(e)
	}
	if _, e := readProtected(path, 2); e == nil {
		t.Fatal("oversize accepted")
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readProtected(link, 10); e == nil {
		t.Fatal("symlink accepted")
	}
	if e := os.Chmod(path, 0o644); e != nil {
		t.Fatal(e)
	}
	if _, e := readProtected(path, 10); e == nil {
		t.Fatal("public file accepted")
	}
	if e := os.Chmod(path, 0o600); e != nil {
		t.Fatal(e)
	}
	hard := filepath.Join(dir, "hard")
	if e := os.Link(path, hard); e != nil {
		t.Fatal(e)
	}
	if _, e := readProtected(path, 10); e == nil {
		t.Fatal("multiply linked file accepted")
	}
}

func TestOriginCookieIsolationRequiresDistinctHosts(t *testing.T) {
	c := config{Issuer: "https://hub.example.test:8443", Origin: "https://hub.example.test:9443", Callback: "https://hub.example.test:9443/callback", ClientID: "client", ProjectID: testProject}
	if e := c.validate(); e == nil {
		t.Fatal("ports do not isolate host-only cookies")
	}
	c.Origin = "https://HUB.example.test.:9443"
	c.Callback = c.Origin + "/callback"
	if e := c.validate(); e == nil {
		t.Fatal("host normalization bypass")
	}
	c.Origin = "https://app.example.test:9443"
	c.Callback = c.Origin + "/callback"
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
}

func TestRejectNoncanonicalBrowserOrigins(t *testing.T) {
	for _, raw := range []string{"HTTPS://hub.example.test", "https://HUB.example.test", "https://hub.example.test:443", "https://hub.example.test.", "https://hub.example.test:08443", "https://hub.example.test:", "https://bücher.example", "https://2130706433", "https://127.000.0.1", "https://0x7f000001", "https://[0:0:0:0:0:0:0:1]:8443", "https://hub.example.test#"} {
		if _, e := originURL(raw); e == nil {
			t.Fatalf("accepted noncanonical origin %s", raw)
		}
	}
	for _, raw := range []string{"https://hub.example.test", "https://hub.example.test:8443", "https://127.0.0.1:8443", "https://[::1]:8443", "https://xn--bcher-kva.example"} {
		if _, e := originURL(raw); e != nil {
			t.Fatalf("canonical origin rejected %s", raw)
		}
	}
}

func TestRejectAlternateNumericConfigHosts(t *testing.T) {
	for _, host := range []string{
		"0x", "0xffffffffffffffff", "0x10000000000000000",
		"app.0x10000000000000000", "0x" + strings.Repeat("f", 61),
	} {
		t.Run(host, func(t *testing.T) {
			for _, pair := range [][2]string{
				{"https://" + host, "https://app.example.test"},
				{"https://hub.example.test", "https://" + host},
			} {
				c := config{
					Issuer: pair[0], Origin: pair[1], Callback: pair[1] + "/callback",
					ClientID: "client", ProjectID: testProject,
				}
				if err := c.validate(); err == nil {
					t.Fatalf("accepted issuer %s and origin %s", c.Issuer, c.Origin)
				}
			}
		})
	}
	for _, raw := range []string{"https://app.0x1g", "https://0x10000000000000000g"} {
		if _, err := originURL(raw); err != nil {
			t.Fatalf("rejected nonnumeric DNS origin %s", raw)
		}
	}
}

func TestCanonicalStandOrigins(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://admin.localhost:8443", "https://content.localhost:9446"},
		{"https://127.0.0.1:8443", "https://127.0.0.3:9446"},
	} {
		c := config{
			Issuer: pair[0], Origin: pair[1], Callback: pair[1] + "/callback",
			ClientID: "client", ProjectID: testProject,
		}
		if err := c.validate(); err != nil {
			t.Fatalf("rejected stand issuer %s and origin %s: %v", c.Issuer, c.Origin, err)
		}
		if c.Issuer != pair[0] || c.Origin != pair[1] || c.Callback != pair[1]+"/callback" {
			t.Fatal("canonical stand configuration was changed")
		}
	}
}
