//nolint:goconst // Explicit option names and malformed values identify each boundary.
package browser

import (
	"bytes"
	"database/sql"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func optionTestStore() *PostgresStore {
	// Constructor tests never query this handle. Only this same-package fixture
	// can fabricate the private wrapper; production uses NewPostgresStore.
	return &PostgresStore{store: &store{db: new(sql.DB)}}
}

func validTestOptions() []Option {
	return []Option{
		WithIssuer("https://issuer.test"),
		WithClientID("client-123"),
		WithProjectID(testProject),
		WithOrigin("https://app.test"),
		WithCallback("https://app.test/callback"),
		WithStore(optionTestStore()),
		WithClientSecret("client-secret"),
		WithStorageKey(bytes.Repeat([]byte("k"), 32)),
	}
}

func testIssuerRoots(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "issuer.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOptionsRequireEveryExplicitInput(t *testing.T) {
	names := []string{"issuer", "client ID", "project ID", "origin", "callback", "store", "client secret", "storage key"}
	for index, name := range names {
		t.Run(name, func(t *testing.T) {
			values := validTestOptions()
			values = append(values[:index], values[index+1:]...)
			_, err := NewWithOptions(t.Context(), values...)
			if err == nil || err.Error() != "missing "+name+" option" {
				t.Fatalf("missing input was not rejected before discovery: %v", err)
			}
		})
	}
}

func TestOptionsRejectNilDuplicatesAndConflicts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value Option
		want  string
	}{
		{"nil", nil, "nil client option"},
		{"same issuer", WithIssuer("https://issuer.test"), "duplicate issuer option"},
		{"conflicting issuer", WithIssuer("https://other.test"), "duplicate issuer option"},
		{"conflicting key", WithStorageKey(bytes.Repeat([]byte("x"), 32)), "duplicate storage key option"},
		{"conflicting store", WithStore(optionTestStore()), "duplicate store option"},
		{"secret does not leak", WithClientSecret("never-print-this-value"), "duplicate client secret option"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := append(validTestOptions(), tc.value)
			_, err := NewWithOptions(t.Context(), values...)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
	for _, value := range []Option{
		WithFreshness(time.Minute), WithIssuerCAFile("unused"),
		WithIngress(nil), WithRevocationEndpoint("https://issuer.test/revoke"),
		WithCentralLogoutURL("https://issuer.test/sign-out"),
	} {
		values := append(validTestOptions(), value, value)
		if _, _, err := buildOptions(values); err == nil || !strings.HasPrefix(err.Error(), "duplicate ") {
			t.Fatal("duplicate optional setting accepted", err)
		}
	}
}

func TestOptionsRejectMalformedInputs(t *testing.T) {
	var absent *PostgresStore
	for _, tc := range []struct {
		name  string
		index int
		value Option
	}{
		{"insecure issuer", 0, WithIssuer("http://issuer.test")},
		{"empty client", 1, WithClientID("")},
		{"bad project", 2, WithProjectID("invalid")},
		{"same host", 3, WithOrigin("https://issuer.test")},
		{"wrong callback", 4, WithCallback("https://app.test/other")},
		{"typed nil store", 5, WithStore(absent)},
		{"zero store", 5, WithStore(&PostgresStore{})},
		{"nil database", 5, WithStore(&PostgresStore{store: &store{}})},
		{"empty secret", 6, WithClientSecret("")},
		{"oversize secret", 6, WithClientSecret(strings.Repeat("s", 4097))},
		{"short key", 7, WithStorageKey(make([]byte, 31))},
		{"nil key", 7, WithStorageKey(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := validTestOptions()
			values[tc.index] = tc.value
			if _, _, err := buildOptions(values); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
	for _, value := range []Option{
		WithFreshness(-time.Second), WithFreshness(5*time.Minute + time.Nanosecond),
		WithRevocationEndpoint(""), WithCentralLogoutURL(""),
		WithRevocationEndpoint("https://other.test/revoke"),
		WithCentralLogoutURL("https://other.test/sign-out"),
	} {
		if _, _, err := buildOptions(append(validTestOptions(), value)); err == nil {
			t.Fatal("malformed optional input accepted")
		}
	}
}

func TestStorageKeyOptionCopiesInputsAndCanBeReused(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	values := validTestOptions()
	values[7] = WithStorageKey(key)
	key[0] = 'x'
	c, first, err := buildOptions(values)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.StorageKey, bytes.Repeat([]byte("k"), 32)) {
		t.Fatal("option retained caller's key slice")
	}
	first.StorageKey[0] = 'y'
	c.Issuer = "https://changed.test"
	nextConfig, next, err := buildOptions(values)
	if err != nil {
		t.Fatal(err)
	}
	if next.StorageKey[0] != 'k' || nextConfig.Issuer != "https://issuer.test" || nextConfig.Issuer == c.Issuer {
		t.Fatal("reusing options retained previous build mutations")
	}
}

func TestNewWithOptionsFreezesInputsAndUsesDiscovery(t *testing.T) {
	authority := newAuthority(t)
	key := bytes.Repeat([]byte("k"), 32)
	sharedStore := optionTestStore()
	db := sharedStore.store.db
	values := validTestOptions()
	values[0] = WithIssuer(authority.server.URL)
	values[5] = WithStore(sharedStore)
	values[7] = WithStorageKey(key)
	values = append(values, WithIssuerCAFile(testIssuerRoots(t, authority.server)))
	client, err := NewWithOptions(t.Context(), values...)
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 'x'
	sharedStore.store.db = nil
	if client.app.store.db != db {
		t.Fatal("constructed client retained mutable store wrapper")
	}
	if client.app.config.RevocationEndpoint != authority.server.URL+"/oauth2/revoke" ||
		client.app.config.CentralLogoutURL != "" {
		t.Fatal("discovery or optional central logout contract changed")
	}
	protected, err := seal(client.app.aead, "synthetic", "unchanged-binding")
	if err != nil {
		t.Fatal(err)
	}
	original, err := newAEAD(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	if value, err := unseal(original, protected, "unchanged-binding"); err != nil || value != "synthetic" {
		t.Fatal("constructor retained caller's storage key", err)
	}
	other, err := NewWithOptions(t.Context(),
		WithIssuer(authority.server.URL), WithClientID("client-123"),
		WithProjectID(testProject), WithOrigin("https://app.test"),
		WithCallback("https://app.test/callback"), WithStore(optionTestStore()),
		WithClientSecret("client-secret"), WithStorageKey(bytes.Repeat([]byte("k"), 32)),
		WithIssuerCAFile(testIssuerRoots(t, authority.server)),
		WithRevocationEndpoint(authority.server.URL+"/custom-revoke"),
		WithCentralLogoutURL(authority.server.URL+"/confirm-sign-out"),
	)
	if err != nil || other == nil {
		t.Fatal("explicit endpoint options rejected", err)
	}
	if other.app.config.RevocationEndpoint != authority.server.URL+"/custom-revoke" ||
		other.app.config.CentralLogoutURL != authority.server.URL+"/confirm-sign-out" {
		t.Fatal("explicit endpoint selection lost")
	}
}
