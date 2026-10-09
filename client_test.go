package browser

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPublicProofFixedDeadlineAndValidityBoundary(t *testing.T) {
	a, authority, _ := testApp(t)
	cookie, _ := signedIn(t, a, authority)
	c := &Client{app: a}
	r := requestForProof(t, a, cookie)
	p, e := c.Verify(r)
	if e != nil {
		t.Fatal(e)
	}
	if p.SessionReference() == "" || p.Generation() <= 0 || p.Deadline().After(a.now().Add(5*time.Minute)) {
		t.Fatal("invalid admission contract")
	}
	if e = c.Valid(t.Context(), p); e != nil {
		t.Fatal(e)
	}
	identity := p.Identity()
	identity.Subject = "local-forgery"
	if identity.Profile == nil {
		identity.Profile = map[string]string{}
	}
	identity.Profile["display"] = "mutated"
	if p.Identity().Subject == identity.Subject || p.Identity().Profile["display"] == "mutated" {
		t.Fatal("proof aliasing")
	}

	binding := p.Binding()
	if restored, e := c.Check(t.Context(), binding); e != nil || !restored.Deadline().Equal(p.Deadline()) {
		t.Fatal("persisted binding failed")
	}
	extended := binding
	extended.Deadline = extended.Deadline.Add(time.Second)
	if _, e = c.Check(t.Context(), extended); !errors.Is(e, ErrDenied) {
		t.Fatal("extended deadline accepted")
	}
	const badIdentity = "other"
	for _, mutation := range []func(*Binding){
		func(b *Binding) { b.Issuer = "https://other.invalid" }, func(b *Binding) { b.Subject = badIdentity },
		func(b *Binding) { b.ProjectID = badIdentity }, func(b *Binding) { b.ClientID = badIdentity },
		func(b *Binding) { b.CentralSessionID = badIdentity }, func(b *Binding) { b.AuthTime++ },
		func(b *Binding) { b.AbsoluteUntil = b.AbsoluteUntil.Add(time.Second) },
	} {
		tampered := binding
		mutation(&tampered)
		if _, e = c.Check(t.Context(), tampered); !errors.Is(e, ErrDenied) {
			t.Fatal("stored identity/absolute tamper accepted")
		}
	}
	replaced := binding
	replaced.Generation++
	if _, e = c.Check(t.Context(), replaced); !errors.Is(e, ErrDenied) {
		t.Fatal("foreign generation accepted")
	}
	if e = c.Valid(t.Context(), Proof{}); !errors.Is(e, ErrDenied) {
		t.Fatal("zero proof accepted")
	}
	original := p.Deadline()
	a.now = func() time.Time { return original }
	if c.Valid(t.Context(), p) == nil {
		t.Fatal("expired snapshot accepted")
	}
	a.now = time.Now
	if e = a.store.end(t.Context(), p.SessionReference(), nil); e != nil {
		t.Fatal(e)
	}
	if c.Valid(t.Context(), p) == nil {
		t.Fatal("logout resurrected admission")
	}
	if _, e = c.Verify(r); e == nil {
		t.Fatal("logout returned proof")
	}
	if !p.Deadline().Equal(original) {
		t.Fatal("proof deadline changed")
	}
}

func requestForProof(t *testing.T, a *app, cookie *http.Cookie) *http.Request {
	t.Helper()
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, a.config.Origin+"/protected", nil)
	r.TLS = &tls.ConnectionState{}
	r.AddCookie(cookie)
	return r
}

func TestPublicProofPendingOwnerAndStorageFailures(t *testing.T) {
	a, p, _ := testApp(t)
	cookie, v := signedIn(t, a, p)
	c := &Client{app: a}
	proof, e := c.Verify(requestForProof(t, a, cookie))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.store.claimRefresh(t.Context(), v, "synthetic-owner"); e != nil {
		t.Fatal(e)
	}
	if e = c.Valid(t.Context(), proof); !errors.Is(e, ErrUnavailable) {
		t.Fatal("claimed owner admitted")
	}
	if _, e = c.Verify(requestForProof(t, a, cookie)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("pending owner error class")
	}
	if e = a.store.db.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Check(t.Context(), proof.Binding()); !errors.Is(e, ErrUnavailable) {
		t.Fatal("storage outage must fail closed as unavailable")
	}
}

const (
	publicTestOrigin    = "https://app.test"
	duplicateCookieCase = "duplicate-cookie"
	plainHTTPCase       = "plain-http"
)

func TestPublicVerifyRejectsForgedIngressBeforeStorage(t *testing.T) {
	c := &Client{app: &app{config: config{Origin: publicTestOrigin}, slots: make(chan struct{}, 1)}}
	for _, kind := range []string{plainHTTPCase, "wrong-host", "oversize", duplicateCookieCase} {
		t.Run(kind, func(t *testing.T) {
			r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.test/private", nil)
			r.TLS = &tls.ConnectionState{}
			r.AddCookie(&http.Cookie{
				Name: cookieName, Value: strings.Repeat("a", 43),
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			switch kind {
			case plainHTTPCase:
				r.TLS = nil
				r.Header.Set("X-Forwarded-Proto", "https")
			case "wrong-host":
				r.Host = "forged.invalid"
			case "oversize":
				r.RequestURI = strings.Repeat("x", 8193)
			case duplicateCookieCase:
				r.AddCookie(&http.Cookie{
					Name: cookieName, Value: strings.Repeat("b", 43),
					Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
				})
			}
			if _, e := c.Verify(r); !errors.Is(e, ErrDenied) {
				t.Fatal("untrusted request reached nil store")
			}
		})
	}
}
