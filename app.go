package browser

import (
	"context"
	"crypto/cipher"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	cookieName    = "__Host-sso-example"
	sessionActive = "active"
	refreshReady  = "ready"
)

var (
	errRefreshPending      = errors.New("refresh outcome is unresolved")
	errTerminalUnconfirmed = errors.New("terminal session write is unconfirmed")
)

type app struct {
	config config
	oidc   *oidcClient
	store  *store
	aead   cipher.AEAD
	now    func() time.Time
	slots  chan struct{}
	render func(http.ResponseWriter, *http.Request, View)
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Keep the exact Origin on HTTPS form POSTs without leaking paths or queries
	// in Referer. no-referrer makes native form submissions send Origin: null.
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	policy := "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' " + a.config.Issuer
	policy += "; base-uri 'none'; frame-ancestors 'none'"
	w.Header().Set("Content-Security-Policy", policy)
	u, _ := url.Parse(a.config.Origin)
	if (r.TLS == nil && !a.config.Ingress.Allows(r)) || r.Host != u.Host || len(r.RequestURI) > 8192 {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		http.Error(w, "Please try again later", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		a.home(w, r)
	case r.URL.Path == "/login" && r.Method == http.MethodPost:
		a.login(w, r)
	case r.URL.Path == "/callback" && r.Method == http.MethodGet:
		a.callback(w, r)
	case r.URL.Path == "/logout" && r.Method == http.MethodPost:
		a.logout(w, r)
	default:
		http.NotFound(w, r)
	}
}

func browserID(r *http.Request) (string, error) {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == cookieName {
			count++
			value = c.Value
		}
	}
	if count != 1 || len(value) != 43 {
		return "", errors.New("missing browser binding")
	}
	return digest(value), nil
}

func (a *app) browser(r *http.Request) (session, error) {
	id, e := browserID(r)
	if e != nil {
		return session{}, e
	}
	return a.store.load(r.Context(), id)
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	v, e := a.browser(r)
	if e != nil {
		if !errors.Is(e, sql.ErrNoRows) {
			if _, e = browserID(r); e == nil {
				http.Error(w, "Session storage unavailable", http.StatusServiceUnavailable)
				return
			}
		}
	}
	if e != nil || v.Status == "ended" || !a.now().Before(v.AbsoluteUntil) {
		secret, e := randomSecret()
		if e != nil {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		csrf, e := randomSecret()
		if e != nil {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		until := a.now().Add(7 * 24 * time.Hour)
		if e = a.store.create(r.Context(), digest(secret), csrf, until); e != nil {
			http.Error(w, "Session storage unavailable", http.StatusServiceUnavailable)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    secret,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  until,
			MaxAge:   7 * 24 * 60 * 60,
		})
		v = session{ID: digest(secret), Status: "pending", CSRF: csrf, AbsoluteUntil: until}
	}
	status := http.StatusOK
	if v.Status == sessionActive {
		v, e = a.authorize(r.Context(), v)
		if e != nil {
			if errors.Is(e, errRefreshPending) || errors.Is(e, errTerminalUnconfirmed) {
				w.Header().Set("Retry-After", "1")
				status = http.StatusServiceUnavailable
			} else {
				status = http.StatusUnauthorized
			}
			// The existing explicit CSRF form permits a new generation after a lost
			// owner, but no cached identity is displayed as authorized on this page.
			v.Proof = nil
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	a.render(w, r, View{CSRF: v.CSRF, Proof: a.proof(v), CentralLogout: a.config.CentralLogoutURL})
}

func parseForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.URL.RawQuery != "" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return nil, errors.New("invalid form")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if e := r.ParseForm(); e != nil {
		return nil, e
	}
	if len(r.PostForm) > 4 {
		return nil, errors.New("too many fields")
	}
	for k, v := range r.PostForm {
		if len(k) > 64 || len(v) != 1 || len(v[0]) > 512 {
			return nil, errors.New("invalid field")
		}
	}
	return r.PostForm, nil
}

func (a *app) formSession(w http.ResponseWriter, r *http.Request) (session, url.Values, error) {
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin ||
		(r.Header.Get("Sec-Fetch-Site") != "" &&
			r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		return session{}, nil, errors.New("invalid origin")
	}
	f, e := parseForm(w, r)
	if e != nil {
		return session{}, nil, e
	}
	v, e := a.browser(r)
	if e != nil {
		return session{}, nil, e
	}
	if subtle.ConstantTimeCompare([]byte(f.Get("csrf")), []byte(v.CSRF)) != 1 {
		return session{}, nil, errors.New("invalid CSRF")
	}
	return v, f, nil
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	v, f, e := a.formSession(w, r)
	if e != nil || v.Status == "ended" {
		http.Error(w, "Invalid sign-in request; reload the app", http.StatusBadRequest)
		return
	}
	state, e := randomSecret()
	if e != nil {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, e := randomSecret()
	if e != nil {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier := oauth2.GenerateVerifier()
	l := login{
		State:      digest(state),
		SessionID:  v.ID,
		Nonce:      nonce,
		ReturnPath: safeReturn(f.Get("return")),
		Expires:    a.now().Add(5 * time.Minute),
	}
	l.Verifier, e = seal(a.aead, verifier, l.binding())
	if e != nil {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	if e = a.store.begin(r.Context(), &l); e != nil {
		http.Error(w, "Cannot start sign-in; reload the app", http.StatusServiceUnavailable)
		return
	}
	target := a.oidc.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(q) > 8 || len(q.Get("state")) != 43 {
		http.Error(w, "Invalid callback", http.StatusBadRequest)
		return
	}
	for k, v := range q {
		if len(k) > 64 || len(v) != 1 || len(v[0]) > 4096 {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
	}
	id, e := browserID(r)
	if e != nil {
		http.Error(w, "Sign-in browser binding was lost", http.StatusBadRequest)
		return
	}
	l, e := a.store.claimLogin(r.Context(), digest(q.Get("state")), id)
	if e != nil {
		http.Error(w, "Sign-in expired or already used", http.StatusBadRequest)
		return
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		http.Error(w, "Sign-in was not completed; return to the app", http.StatusUnauthorized)
		return
	}
	verifier, e := unseal(a.aead, l.Verifier, l.binding())
	if e != nil {
		http.Error(w, "Sign-in state unavailable", http.StatusServiceUnavailable)
		return
	}
	token, e := a.oidc.oauth.Exchange(a.oidc.context(r.Context()), q.Get("code"), oauth2.VerifierOption(verifier))
	// The consumed transaction is never retried, including an unknown exchange.
	if e != nil {
		http.Error(w, "Sign-in failed; start a new sign-in", http.StatusUnauthorized)
		return
	}
	p, e := a.oidc.verify(r.Context(), token, l.Nonce, nil)
	if e != nil || token.RefreshToken == "" || len(token.RefreshToken) > 4096 {
		a.discard(r.Context(), token.RefreshToken)
		http.Error(w, "Invalid identity proof", http.StatusUnauthorized)
		return
	}
	v := session{ID: id, Generation: l.Generation}
	encrypted, e := seal(a.aead, token.RefreshToken, v.binding())
	if e == nil {
		e = a.store.installLogin(r.Context(), l, p, encrypted)
	}
	if e != nil {
		a.discard(r.Context(), token.RefreshToken)
		http.Error(w, "Sign-in was superseded; return to the app", http.StatusUnauthorized)
		return
	}
	// Installation is one committed transition, not an HTTP-delivery promise.
	// Re-read the current row so its conservative absolute end and any generation
	// fence apply to this acknowledgement. Never claim a rollback after commit.
	current, e := a.store.load(r.Context(), id)
	if e != nil {
		http.Error(w, "Sign-in acknowledgement unavailable", http.StatusServiceUnavailable)
		return
	}
	if current.Status != sessionActive || current.Generation != l.Generation ||
		current.Proof == nil || current.RefreshState == "claimed" {
		http.Error(w, "Sign-in was superseded; return to the app", http.StatusUnauthorized)
		return
	}
	if !a.now().Before(minTime(current.FreshUntil, current.AbsoluteUntil)) {
		http.Error(w, "Sign-in proof expired before acknowledgement; return to the app", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, l.ReturnPath, http.StatusSeeOther)
}

func (a *app) discard(parent context.Context, secret string) {
	// A canceled browser request must not cancel bounded cleanup of its abandoned family.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 8*time.Second)
	defer cancel()
	_ = a.oidc.revoke(ctx, secret)
}

func (a *app) authorize(ctx context.Context, v session) (session, error) {
	if v.Status != sessionActive || v.Proof == nil {
		return v, errFenced
	}
	if v.Proof.Issuer != a.config.Issuer || v.Proof.ClientID != a.config.ClientID || v.Proof.ProjectID != a.config.ProjectID {
		return v, a.terminate(ctx, v)
	}
	if !a.now().Before(v.AbsoluteUntil) {
		return v, a.terminate(ctx, v)
	}
	// Refresh shortly before expiry. Only the durable winner sends a request.
	lead := a.config.Freshness / 10
	if lead == 0 {
		lead = 30 * time.Second
	}
	if !a.now().Before(v.FreshUntil.Add(-lead)) && v.RefreshState == refreshReady {
		if e := a.refresh(ctx, v); e != nil {
			return v, e
		}
	}

	// Re-read after the network boundary: logout or another owner may have won.
	current, e := a.store.load(ctx, v.ID)
	if e != nil {
		return session{}, e
	}
	if current.Status != sessionActive || current.Proof == nil {
		return current, errFenced
	}
	if current.Proof.Issuer != a.config.Issuer ||
		current.Proof.ClientID != a.config.ClientID ||
		current.Proof.ProjectID != a.config.ProjectID {
		return current, a.terminate(ctx, current)
	}
	if !a.now().Before(current.AbsoluteUntil) {
		return current, a.terminate(ctx, current)
	}
	if current.RefreshState != refreshReady && current.RefreshState != "uncertain" {
		return current, errRefreshPending
	}
	if !a.now().Before(current.FreshUntil) {
		return current, errFenced
	}
	return current, nil
}

func (a *app) refresh(ctx context.Context, v session) error {
	owner, e := randomSecret()
	if e != nil {
		return e
	}
	won, e := a.store.claimRefresh(ctx, v, owner)
	if e != nil || !won {
		return e
	}
	old, e := unseal(a.aead, v.Cipher, v.binding())
	if e != nil {
		return a.terminate(ctx, v)
	}
	// One temporary TokenSource, one call; never retained or independently retried.
	next, e := a.oidc.oauth.TokenSource(a.oidc.context(ctx), &oauth2.Token{RefreshToken: old}).Token()
	if e != nil {
		if definitive(e) {
			return a.terminate(ctx, v)
		}
		return a.store.uncertain(ctx, v, owner)
	}
	p, verifyErr := a.oidc.verify(ctx, next, "", v.Proof)
	if !a.now().Before(v.AbsoluteUntil) {
		verifyErr = errFenced
	}
	// oauth2 copies the old secret if the server omits it. Rotation requires a new one.
	if verifyErr != nil || next.RefreshToken == "" || len(next.RefreshToken) > 4096 || next.RefreshToken == old {
		terminalErr := a.terminate(ctx, v)
		a.discard(ctx, next.RefreshToken)
		return terminalErr
	}
	updated := v
	updated.Generation++
	encrypted, e := seal(a.aead, next.RefreshToken, updated.binding())
	if e == nil {
		e = a.store.installRefresh(ctx, v, owner, p, encrypted)
	}
	if e != nil {
		a.discard(ctx, next.RefreshToken)
	}
	return e
}

func (a *app) terminate(parent context.Context, v session) error {
	// Known denial must survive browser cancellation. The already-claimed row
	// remains fail closed if this bounded write cannot be confirmed.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	if e := a.store.end(ctx, v.ID, &v.Generation); e != nil && !errors.Is(e, errFenced) {
		return errTerminalUnconfirmed
	}
	return errFenced
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	v, _, e := a.formSession(w, r)
	if e != nil {
		http.Error(w, "Invalid sign-out request", http.StatusBadRequest)
		return
	}
	a.logoutSession(w, r, v)
}

// logoutSession carries the form-authenticated snapshot across the terminal write.
// It must not re-read a newer login and turn an old request into new logout intent.
func (a *app) logoutSession(w http.ResponseWriter, r *http.Request, v session) {
	location := "/"
	var e error
	if v.Status == sessionActive && v.Proof != nil {
		// Logout is allowed after freshness expiry; unlike admission, this snapshot
		// does not use proof(), authorize(), or refresh before capturing the pins.
		p := Proof{
			identity: *v.Proof, reference: v.ID, generation: v.Generation,
			loginGeneration: v.LoginGeneration, deadline: minTime(v.FreshUntil, v.AbsoluteUntil),
		}
		p.identity.AbsoluteUntil = minTime(v.AbsoluteUntil, p.identity.AbsoluteUntil)
		e = (&Client{app: a}).RevokeBinding(r.Context(), p.Binding())
		w.Header().Set("X-AuthHub-Logout-Scope", "binding-revoked")
	} else {
		// Anonymous/pending/ended rows have no verified remote family to revoke.
		// Exact generation AND status CAS fences a callback installed after this form.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		e = a.store.endLocal(ctx, v)
		cancel()
		e = publicError(e)
		w.Header().Set("X-AuthHub-Logout-Scope", "local-only")
		location = "/?logout=local-only"
	}
	if e != nil && !errors.Is(e, ErrRevocationUnconfirmed) {
		w.Header().Set("X-AuthHub-Logout-Scope", "unconfirmed")
		if errors.Is(e, ErrDenied) {
			http.Error(w, "Sign-out was superseded; current browser session preserved", http.StatusConflict)
		} else {
			http.Error(w, "Local sign-out could not be confirmed", http.StatusServiceUnavailable)
		}
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	if errors.Is(e, ErrRevocationUnconfirmed) {
		w.Header().Set("X-AuthHub-Logout-Scope", "local-only")
		http.Error(w, "Local sign-out complete; central revocation unconfirmed", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}
