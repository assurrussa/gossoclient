//nolint:tagliatelle // OIDC wire and stored proof fields deliberately retain protocol snake_case.
package browser

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const maxResponse = 128 << 10

// The official libraries read discovery/JWKS/token responses. Bound all of those
// reads at the transport boundary, including chunked responses and decompression.
type requestBudget struct {
	mu     sync.Mutex
	second int64
	count  int
	slots  chan struct{}
}
type boundedTransport struct {
	base   http.RoundTripper
	origin string
	budget *requestBudget
}
type boundedBody struct {
	io.ReadCloser
	remaining int64
	release   func()
	once      sync.Once
}

func (b *boundedBody) done() {
	b.once.Do(func() {
		if b.release != nil {
			b.release()
		}
	})
}
func (b *boundedBody) Close() error { e := b.ReadCloser.Close(); b.done(); return e }
func (b *boundedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, e := b.ReadCloser.Read(p)
	if int64(n) > b.remaining {
		_ = b.Close()
		return 0, errors.New("issuer response exceeds limit")
	}
	b.remaining -= int64(n)
	if e != nil {
		b.done()
	}
	return n, e
}

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	release := func() {}
	if t.budget != nil {
		t.budget.mu.Lock()
		second := time.Now().Unix()
		if second != t.budget.second {
			t.budget.second = second
			t.budget.count = 0
		}
		t.budget.count++
		allowed := t.budget.count <= 20
		t.budget.mu.Unlock()
		if !allowed {
			return nil, errors.New("issuer request rate exceeded")
		}
		select {
		case t.budget.slots <- struct{}{}:
			release = func() { <-t.budget.slots }
		default:
			return nil, errors.New("issuer request concurrency exceeded")
		}
	}
	if r.URL.Scheme+"://"+r.URL.Host != t.origin || r.URL.User != nil || r.URL.Fragment != "" {
		release()
		return nil, errors.New("issuer request outside configured origin")
	}
	res, e := t.base.RoundTrip(r)
	if e != nil {
		release()
		return nil, e
	}
	if res.ContentLength > maxResponse {
		_ = res.Body.Close()
		release()
		return nil, errors.New("issuer response exceeds limit")
	}
	res.Body = &boundedBody{ReadCloser: res.Body, remaining: maxResponse, release: release}
	return res, nil
}

// Identity contains independently verified OIDC identity claims.
type Identity struct {
	// AuthHubIdentifiers is only populated from the dedicated, signed claim.
	// Profile and standard email/username claims never supply this authority.
	AuthHubIdentifiers *CanonicalIdentifiers `json:"authhub_identifiers,omitempty"`
	Issuer             string                `json:"issuer"`
	ClientID           string                `json:"client_id"`
	Subject            string                `json:"subject"`
	ProjectID          string                `json:"project_id"`
	SessionID          string                `json:"sid"`
	AuthTime           int64                 `json:"auth_time"`
	IssuedAt           time.Time             `json:"issued_at"`
	FreshUntil         time.Time             `json:"fresh_until"`
	AbsoluteUntil      time.Time             `json:"absolute_until"`
	Profile            map[string]string     `json:"profile,omitempty"`
	Project            map[string]string     `json:"project,omitempty"`
}
type identity = Identity

type oidcClient struct {
	config   config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	http     *http.Client
	now      func() time.Time
}

func newOIDC(
	ctx context.Context, c config, secret string, transport http.RoundTripper, now func() time.Time,
) (*oidcClient, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	if secret == "" || len(secret) > 4096 {
		return nil, errors.New("client secret is required")
	}
	// Discovery can leave a keep-alive connection behind even when later
	// validation fails. Close only our own pool on failure; a successful client
	// retains it, and an injected transport always remains caller-owned.
	var ownedTransport *http.Transport
	defer func() {
		if ownedTransport != nil {
			ownedTransport.CloseIdleConnections()
		}
	}()
	if transport == nil {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("unexpected default HTTP transport")
		}
		production := base.Clone()
		ownedTransport = production
		production.Proxy = nil
		production.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		if c.IssuerCAFile != "" {
			roots, e := readIssuerRoots(c.IssuerCAFile)
			if e != nil {
				return nil, e
			}
			production.TLSClientConfig.RootCAs = roots
		}
		production.ResponseHeaderTimeout = 5 * time.Second
		production.MaxConnsPerHost = 4
		production.MaxIdleConnsPerHost = 4
		transport = production
	}
	client := &http.Client{
		Transport:     boundedTransport{transport, c.Issuer, &requestBudget{slots: make(chan struct{}, 4)}},
		Timeout:       8 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("issuer redirects are forbidden") },
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, e := oidc.NewProvider(ctx, c.Issuer)
	if e != nil {
		return nil, errors.New("OIDC discovery failed")
	}
	var meta struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
		Revoke string `json:"revocation_endpoint"`
	}
	if e = provider.Claims(&meta); e != nil {
		return nil, e
	}
	ep := provider.Endpoint()
	// AuthStyleAutoDetect retries after ANY error, including a lost response.
	ep.AuthStyle = oauth2.AuthStyleInHeader
	for _, endpoint := range []string{ep.AuthURL, ep.TokenURL, meta.JWKS} {
		if e = validateIssuerEndpoint(endpoint, c.Issuer); e != nil {
			return nil, errors.New("discovery endpoint is not pinned to issuer")
		}
	}
	// An explicit endpoint wins. Otherwise discovery must supply one; never
	// guess a provider-specific path or silently disable remote revocation.
	if c.RevocationEndpoint == "" {
		c.RevocationEndpoint = meta.Revoke
	}
	if e = validateIssuerEndpoint(c.RevocationEndpoint, c.Issuer); e != nil {
		return nil, errors.New("explicit or discovered issuer-pinned revocation endpoint required")
	}
	if meta.Issuer != c.Issuer {
		return nil, errors.New("discovery issuer mismatch")
	}
	result := &oidcClient{
		config: c,
		oauth: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: secret, Endpoint: ep, RedirectURL: c.Callback,
			Scopes: []string{oidc.ScopeOpenID, "profile"},
		},
		verifier: provider.Verifier(&oidc.Config{
			ClientID: c.ClientID, SupportedSigningAlgs: []string{oidc.RS256}, Now: now,
		}),
		http: client, now: now,
	}
	ownedTransport = nil // Transfer the owned pool to the successfully constructed client.
	return result, nil
}

func (c *oidcClient) context(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, c.http)
}

func (c *oidcClient) verify(ctx context.Context, token *oauth2.Token, nonce string, prior *identity) (identity, error) {
	fail := func() (identity, error) { return identity{}, errors.New("invalid identity proof") }
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" || len(raw) > 32768 {
		return fail()
	}
	id, e := c.verifier.Verify(c.context(ctx), raw)
	if e != nil {
		return fail()
	}
	var claims struct {
		Identifiers json.RawMessage   `json:"authhub_identifiers"`
		ProjectID   string            `json:"project_id"`
		Purpose     string            `json:"token_use"`
		SID         string            `json:"sid"`
		AuthTime    int64             `json:"auth_time"`
		Profile     map[string]string `json:"authhub_profile"`
		Project     map[string]string `json:"authhub_project"`
	}
	if id.Claims(&claims) != nil ||
		!validTokenIdentity(id, c.config) ||
		!c.config.allowsProject(claims.ProjectID) ||
		claims.Purpose != "id" ||
		!uuidPattern.MatchString(claims.SID) ||
		claims.AuthTime <= 0 {
		return fail()
	}
	identifiers, valid := parseCanonicalIdentifiers(claims.Identifiers)
	if !valid {
		return fail()
	}
	if nonce != "" && id.Nonce != nonce {
		return fail()
	}
	now := c.now()
	if id.IssuedAt.IsZero() ||
		id.IssuedAt.After(now.Add(30*time.Second)) ||
		!id.Expiry.After(id.IssuedAt) ||
		claims.AuthTime > id.IssuedAt.Unix()+30 {
		return fail()
	}
	freshnessCap := c.freshnessLimit()
	fresh := minTime(id.Expiry, id.IssuedAt.Add(freshnessCap), now.Add(freshnessCap))
	absolute := time.Unix(claims.AuthTime, 0).Add(7 * 24 * time.Hour)
	if prior != nil {
		if id.Issuer != prior.Issuer ||
			c.config.ClientID != prior.ClientID ||
			id.Subject != prior.Subject ||
			claims.ProjectID != prior.ProjectID ||
			claims.SID != prior.SessionID ||
			claims.AuthTime != prior.AuthTime ||
			id.IssuedAt.Before(prior.IssuedAt) {
			return fail()
		}
		absolute = minTime(absolute, prior.AbsoluteUntil)
		if !id.IssuedAt.After(prior.IssuedAt) {
			fresh = minTime(fresh, prior.FreshUntil)
		}
	}
	fresh = minTime(fresh, absolute)
	if !now.Before(fresh) || !validMetadata(claims.Profile) || !validMetadata(claims.Project) {
		return fail()
	}
	return identity{
		AuthHubIdentifiers: identifiers,
		Issuer:             id.Issuer,
		ClientID:           c.config.ClientID,
		Subject:            id.Subject,
		ProjectID:          claims.ProjectID,
		SessionID:          claims.SID,
		AuthTime:           claims.AuthTime,
		IssuedAt:           id.IssuedAt,
		FreshUntil:         fresh,
		AbsoluteUntil:      absolute,
		Profile:            claims.Profile,
		Project:            claims.Project,
	}, nil
}

func (c *oidcClient) freshnessLimit() time.Duration {
	freshnessCap := c.config.Freshness
	if freshnessCap == 0 {
		freshnessCap = 5 * time.Minute
	}
	return freshnessCap
}

func minTime(first time.Time, rest ...time.Time) time.Time {
	for _, v := range rest {
		if v.Before(first) {
			first = v
		}
	}
	return first
}

func validMetadata(m map[string]string) bool {
	if len(m) > 8 {
		return false
	}
	total := 0
	for k, v := range m {
		if len(k) < 1 || len(k) > 32 || len(v) > 256 || !utf8.ValidString(v) {
			return false
		}
		for i, b := range []byte(k) {
			letter := b >= 'a' && b <= 'z'
			suffix := i > 0 && (b >= '0' && b <= '9' || b == '_')
			if !letter && !suffix {
				return false
			}
		}
		total += len(k) + len(v)
	}
	return total <= 2048
}

func definitive(err error) bool {
	var e *oauth2.RetrieveError
	return errors.As(err, &e) &&
		(e.ErrorCode == "invalid_grant" ||
			e.ErrorCode == "invalid_client" ||
			e.ErrorCode == "unauthorized_client")
}

func (c *oidcClient) revoke(ctx context.Context, secret string) error {
	if secret == "" {
		return nil
	}
	form := url.Values{"token": {secret}, "token_type_hint": {"refresh_token"}}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.config.RevocationEndpoint, strings.NewReader(form.Encode()))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.oauth.ClientID), url.QueryEscape(c.oauth.ClientSecret))
	res, e := c.http.Do(req)
	if e != nil {
		return errors.New("revocation unavailable")
	}
	defer func() { _ = res.Body.Close() }()
	_, e = io.Copy(io.Discard, res.Body)
	if e != nil || res.StatusCode != http.StatusOK {
		return errors.New("revocation unavailable")
	}
	return nil
}

func validTokenIdentity(id *oidc.IDToken, c config) bool {
	return id.Issuer == c.Issuer && len(id.Audience) == 1 &&
		id.Audience[0] == c.ClientID && id.Subject != "" && len(id.Subject) <= 256
}
