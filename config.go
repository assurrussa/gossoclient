package browser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/assurrussa/gossoclient/ingress"
)

// Private configuration for the reviewed protocol implementation.
type config struct {
	Issuer, ClientID, ProjectID, Origin, Callback  string
	RevocationEndpoint, CentralLogoutURL           string
	ClientSecretFile, StorageKeyFile, DatabaseFile string
	Addr, CertFile, TLSKeyFile                     string
	Freshness                                      time.Duration
	IssuerCAFile                                   string
	Transport, ProxyCIDRs                          string
	Ingress                                        *ingress.Policy
}

const privateHTTPTransport = "private-http"

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func originURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(raw, "https://") ||
		u.Scheme != "https" ||
		u.Hostname() == "" ||
		u.User != nil ||
		u.Path != "" ||
		u.RawPath != "" ||
		u.RawQuery != "" ||
		u.ForceQuery ||
		u.Fragment != "" ||
		strings.ContainsAny(raw, "\\*?#\r\n\t ") {
		return nil, errors.New("expected exact HTTPS origin without trailing slash")
	}
	if !canonicalHost(u) {
		return nil, errors.New("HTTPS host and port must use their canonical browser form")
	}

	return u, nil
}

func canonicalHost(u *url.URL) bool {
	host := u.Hostname()
	if host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.String() != host {
		return false
	}
	if ip == nil && !validDNSHost(host) {
		return false
	}

	expected := host
	if strings.Contains(host, ":") {
		expected = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return false
		}
		expected = net.JoinHostPort(host, port)
	}
	return u.Host == expected
}

func validDNSHost(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if b != '-' && (b < 'a' || b > 'z') && (b < '0' || b > '9') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	// Browsers interpret alternate decimal/octal/hex IPv4 forms as IP addresses.
	if strings.Trim(last, "0123456789") == "" {
		return false
	}
	// Check syntax, not uint64 range: overflowing hexadecimal labels are numeric too.
	if strings.HasPrefix(last, "0x") && strings.Trim(last[2:], "0123456789abcdef") == "" {
		return false
	}
	return true
}

func (c config) validate() error {
	if (c.Transport != "" && c.Transport != "tls" && c.Transport != privateHTTPTransport) ||
		((c.Transport == "" || c.Transport == "tls") && c.ProxyCIDRs != "") ||
		(c.Transport == privateHTTPTransport && (c.ProxyCIDRs == "" || c.CertFile != "" || c.TLSKeyFile != "")) {
		return errors.New("invalid application ingress transport")
	}
	if c.Freshness < 0 || c.Freshness > 5*time.Minute {
		return errors.New("freshness must be positive and at most five minutes")
	}
	issuer, err := originURL(c.Issuer)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	origin, err := originURL(c.Origin)
	if err != nil {
		return fmt.Errorf("origin: %w", err)
	}
	if strings.EqualFold(strings.TrimSuffix(issuer.Hostname(), "."), strings.TrimSuffix(origin.Hostname(), ".")) ||
		c.Callback != c.Origin+"/callback" {
		return errors.New("issuer and app need distinct hostnames; callback must equal app origin + /callback")
	}
	if !uuidPattern.MatchString(c.ProjectID) ||
		c.ProjectID == "00000000-0000-0000-0000-000000000000" ||
		c.ClientID == "" ||
		len(c.ClientID) > 256 ||
		c.ClientID == c.ProjectID {
		return errors.New("distinct client ID and canonical project UUID required")
	}
	for _, endpoint := range []string{c.RevocationEndpoint, c.CentralLogoutURL} {
		if endpoint != "" {
			if err := validateIssuerEndpoint(endpoint, c.Issuer); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateIssuerEndpoint accepts only an explicit path on the pinned HTTPS
// issuer origin. It performs no normalization or network access.
func validateIssuerEndpoint(raw, issuer string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || !strings.HasPrefix(raw, issuer+"/") || u.Scheme != "https" ||
		u.Scheme+"://"+u.Host != issuer || u.User != nil || u.Opaque != "" ||
		u.Path == "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(raw, "\\?#\r\n\t ") ||
		strings.ContainsAny(u.Path, "\\?#\r\n\t ") {
		return errors.New("endpoint must be an exact HTTPS path on the issuer origin without query or fragment")
	}
	return nil
}

// Protected inputs must be deliberately supplied; startup never creates keys.
// Linux O_NOFOLLOW, regular-file and ownership checks avoid a symlink/open race.
func readProtected(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open protected input")
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect protected input")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 ||
		st.Uid != uint32(os.Geteuid()) ||
		st.Nlink != 1 ||
		info.Size() > limit {
		return nil, errors.New("protected input must be owned, single-link, mode 0600 regular file within limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("cannot read protected input")
	}
	return data, nil
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func digest(s string) string {
	d := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("storage key must contain exactly 32 raw bytes")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}

func seal(a cipher.AEAD, plaintext, binding string) ([]byte, error) {
	n := make([]byte, a.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return a.Seal(n, n, []byte(plaintext), []byte(binding)), nil
}

func unseal(a cipher.AEAD, ciphertext []byte, binding string) (string, error) {
	if len(ciphertext) < a.NonceSize() {
		return "", errors.New("invalid protected state")
	}
	b, e := a.Open(nil, ciphertext[:a.NonceSize()], ciphertext[a.NonceSize():], []byte(binding))
	return string(b), e
}

func safeReturn(raw string) string {
	if raw == "" {
		return "/"
	}
	if len(raw) > 512 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\t") {
		return "/"
	}
	u, e := url.Parse(raw)
	if e != nil ||
		u.IsAbs() ||
		u.Host != "" ||
		u.Fragment != "" ||
		strings.ContainsAny(u.Path, "\\\r\n\t") ||
		strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	// This minimal app has one landing page; no arbitrary redirect gateway.
	if u.Path != "/" {
		return "/"
	}
	return u.RequestURI()
}

// AuthHub maintenance delivers this exact protected candidate. Do not extract
// its secret through a shell command or logs. Loading is deliberately restart-bound.
func readClientSecret(path, clientID string) (string, error) {
	data, e := readProtected(path, 8192)
	if e != nil {
		return "", e
	}
	return parseClientSecret(data, clientID)
}

func parseClientSecret(data []byte, clientID string) (string, error) {
	fail := errors.New("invalid client candidate or mismatched client ID")
	dec := json.NewDecoder(bytes.NewReader(data))
	token, e := dec.Token()
	if e != nil || token != json.Delim('{') {
		return "", fail
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		token, e = dec.Token()
		if e != nil {
			return "", fail
		}
		name, ok := token.(string)
		if !ok || fields[name] != nil {
			return "", fail
		}
		if name != "version" && name != "clientId" && name != "secret" {
			return "", fail
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil || bytes.Equal(raw, []byte("null")) {
			return "", fail
		}
		fields[name] = raw
	}
	if _, e = dec.Token(); e != nil {
		return "", fail
	}
	if _, e = dec.Token(); e != io.EOF {
		return "", fail
	}
	var version int
	var id, secret string
	if len(fields) != 3 ||
		json.Unmarshal(fields["version"], &version) != nil ||
		version != 1 ||
		json.Unmarshal(fields["clientId"], &id) != nil ||
		id != clientID ||
		json.Unmarshal(fields["secret"], &secret) != nil ||
		secret == "" ||
		len(secret) > 4096 ||
		strings.ContainsAny(secret, "\r\n\t ") {
		return "", fail
	}
	return secret, nil
}
