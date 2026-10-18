package browser

import "net/http"

// CallbackOutcome is an immutable, successfully committed callback result.
// A zero outcome conveys no authority. Its return path was saved with the
// one-use state/PKCE/browser-bound login, never read from the callback query.
type CallbackOutcome struct {
	proof Proof
	returnPath string
}

// Proof returns a copy of the original, fixed-deadline identity snapshot.
func (o CallbackOutcome) Proof() Proof { return o.proof }

// ReturnPath returns the exact validated root-relative path saved at Begin.
func (o CallbackOutcome) ReturnPath() string { return o.returnPath }

// CallbackResult handles exactly GET /callback using the same ingress, nonce,
// state, PKCE, durable generation and concurrency protections as Callback.
// Success returns only after installation and a current durable re-read; it
// writes security headers but NO success status, body, cookie or redirect.
// The host then owns success delivery and may perform transactional enrollment.
// On error the failure HTTP response is ALREADY written; the host must return
// without writing another response. No outcome may authorize a failed callback.
// This method never calls Verify or refreshes a previous browser session.
func (c *Client) CallbackResult(w http.ResponseWriter, r *http.Request) (CallbackOutcome, error) {
	if r == nil || r.URL == nil || r.URL.Path != "/callback" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return CallbackOutcome{}, ErrDenied
	}
	if c == nil || c.app == nil {
		http.Error(w, "Sign-in unavailable", http.StatusServiceUnavailable)
		return CallbackOutcome{}, ErrUnavailable
	}
	return c.app.serveHTTP(w, r, true)
}
