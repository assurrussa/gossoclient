package browser

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

// LogoutFromHost terminates the current browser's RP session after the host has
// authenticated intentional logout and verified its OWN CSRF token. Never mount
// this method directly as an unauthenticated handler: Origin is defense in depth,
// not a substitute for the host's session-bound CSRF check.
//
// Use this only for a native local host session with no saved external binding.
// For an admitted external session use RevokeBinding with its ORIGINAL binding;
// re-reading the browser here would turn stale host intent into newer login intent.
//
// The request must be POST with the exact configured Origin and trusted ingress.
// No library form/CSRF field is required. The browser snapshot is captured once,
// without Verify, authorization or refresh, and the ordinary Logout terminal
// generation fence and response scopes apply. A missing cookie or missing row
// returns 303 local-only without setting a cookie. Malformed/duplicate cookies,
// invalid ingress/origin and storage errors preserve cookies and fail closed.
func (c *Client) LogoutFromHost(w http.ResponseWriter, r *http.Request) {
	a := c.app
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-AuthHub-Logout-Scope", "unconfirmed")
	if !a.validRequest(r) || r.Method != http.MethodPost ||
		len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin ||
		(r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		http.Error(w, "Invalid sign-out request", http.StatusBadRequest)
		return
	}
	rawCount := 0
	for _, header := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			name, _, _ := strings.Cut(pair, "=")
			if strings.TrimSpace(name) == cookieName {
				rawCount++
			}
		}
	}
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == cookieName {
			count++
		}
	}
	if rawCount != count || count > 1 {
		http.Error(w, "Invalid browser binding", http.StatusBadRequest)
		return
	}
	if count == 0 {
		hostLogoutWithoutSession(w, r)
		return
	}
	if _, err := browserID(r); err != nil {
		http.Error(w, "Invalid browser binding", http.StatusBadRequest)
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		http.Error(w, "Local sign-out could not be confirmed", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	snapshot, err := a.browser(r)
	if errors.Is(err, sql.ErrNoRows) {
		hostLogoutWithoutSession(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Local sign-out could not be confirmed", http.StatusServiceUnavailable)
		return
	}
	a.logoutSession(w, r, snapshot)
}

func hostLogoutWithoutSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-AuthHub-Logout-Scope", "local-only")
	http.Redirect(w, r, "/?logout=local-only", http.StatusSeeOther)
}
