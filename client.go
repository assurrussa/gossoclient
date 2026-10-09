// Package browser implements AuthHub relying-party browser sessions using the
// reviewed OIDC libraries and durable PostgreSQL generation fences. It supplies
// identity proofs, never local user linking or application permissions.
package browser

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/assurrussa/gossoclient/ingress"
)

// ErrDenied means this proof/session cannot authorize the current request.
// Expired, terminal and superseded generations require a new admission.
var ErrDenied = errFenced

// ErrUnavailable means the boundary could not confirm validity. Fail closed;
// do not mint or extend a host session. A later request may retry validity, but
// must never independently replay an OAuth exchange or claimed refresh.
var ErrUnavailable = errors.New("session validity unavailable")

func publicError(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, errFenced) || errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	return ErrUnavailable
}

// Config pins the authority, application origin, client and project. Callback is
// exactly Origin + /callback. Zero Freshness means the reviewed five-minute cap.
// Ingress must be nil for direct TLS or an explicitly constructed trusted edge.
type Config struct {
	Issuer, ClientID, ProjectID, Origin, Callback string
	Freshness                                     time.Duration
	IssuerCAFile                                  string
	Ingress                                       *ingress.Policy
}

func (c Config) internal() config {
	v := config{
		Issuer: c.Issuer, ClientID: c.ClientID, ProjectID: c.ProjectID,
		Origin: c.Origin, Callback: c.Callback, Freshness: c.Freshness,
		IssuerCAFile: c.IssuerCAFile, Ingress: c.Ingress,
	}
	if c.Ingress != nil {
		v.Transport = privateHTTPTransport
		v.ProxyCIDRs = "explicit"
	}
	return v
}

// ValidateConfig checks exact origins and identity pins without network access.
func ValidateConfig(c Config) error { return c.internal().validate() }

// ValidateAuthHubClientConfig checks the same network-free settings for
// WithAuthHubClientBoundProject. ProjectID must be empty; the issuer must satisfy
// that option's immutable-client registration contract.
func ValidateAuthHubClientConfig(c Config) error {
	v := c.internal()
	v.ClientBoundProject = true
	return v.validate()
}

// ValidateIssuerEndpoint checks an explicit provider endpoint without network
// access. Validate application identity/origin settings with ValidateConfig too.
// For an absent optional central logout link, omit this check and its option.
func ValidateIssuerEndpoint(issuer, endpoint string) error {
	if _, err := originURL(issuer); err != nil {
		return err
	}
	return validateIssuerEndpoint(endpoint, issuer)
}

// PostgresStore owns no connection pool. The caller owns db and must apply
// Schema in an application-owned schema before construction. There are no
// authority/internal imports and no automatic migrations.
type PostgresStore struct{ store *store }

// Schema returns the reviewed RP schema. Existing table names are retained for
// compatibility; isolate each application's rows using its PostgreSQL schema.
func Schema() string { return schema }

// NewPostgresStore fails closed on absent or partial durable schema.
func NewPostgresStore(ctx context.Context, db *sql.DB) (*PostgresStore, error) {
	return newPostgresStore(ctx, db, "")
}

// NewPostgresStoreWithSchema borrows the caller's existing pool and qualifies
// every session query with schemaName. The schema must already be migrated;
// construction never opens/closes a pool or changes connection search_path.
// Names are case-sensitive ASCII identifiers of at most 63 bytes.
func NewPostgresStoreWithSchema(ctx context.Context, db *sql.DB, schemaName string) (*PostgresStore, error) {
	if err := validateStoreSchema(schemaName); err != nil {
		return nil, err
	}
	return newPostgresStore(ctx, db, schemaName)
}

func newPostgresStore(ctx context.Context, db *sql.DB, schemaName string) (*PostgresStore, error) {
	if db == nil {
		return nil, errors.New("session database required")
	}
	s := &store{db: db, schema: schemaName}
	if e := s.ready(ctx); e != nil {
		return nil, e
	}
	return &PostgresStore{store: s}, nil
}

// Options supplies protected inputs. New does not log, generate or persist keys.
// Store is mandatory: there is no in-memory fallback. No customizable token
// transport or clock is exposed in the consumer API.
type Options struct {
	Store        *PostgresStore
	ClientSecret string
	StorageKey   []byte
}

// Client is safe for concurrent HTTP use. The caller owns the database lifetime.
type Client struct{ app *app }

// New retains the original AuthHub-profile API and provider-relative logout
// routes for existing callers. New integrations should use NewWithOptions.
// New performs bounded OIDC discovery using the configured issuer trust roots.
func New(ctx context.Context, c Config, o Options) (*Client, error) {
	v := c.internal()
	v.RevocationEndpoint = c.Issuer + "/oauth2/revoke"
	v.CentralLogoutURL = c.Issuer + "/sso/logout"
	return newClient(ctx, v, o)
}

func newClient(ctx context.Context, c config, o Options) (*Client, error) {
	if e := validateInputs(o); e != nil {
		return nil, e
	}
	if e := c.validate(); e != nil {
		return nil, e
	}
	// The database remains caller-owned. Snapshot our wrapper so neither the
	// option object nor constructor inputs can replace the selected handle.
	selectedStore := *o.Store.store
	aead, e := newAEAD(o.StorageKey)
	if e != nil {
		return nil, e
	}
	oidc, e := newOIDC(ctx, c, o.ClientSecret, nil, time.Now)
	if e != nil {
		return nil, e
	}
	return &Client{app: &app{
		config: oidc.config, oidc: oidc, store: &selectedStore, aead: aead,
		now: time.Now, slots: make(chan struct{}, 32),
	}}, nil
}

// Proof is an immutable snapshot minted by Client.Verify or Handler. Copying a
// proof preserves its original deadline. Call Valid at each external session
// admission/validity boundary; do not turn Deadline into a rolling local TTL.
// The reference is opaque app-owned durable state, not the central OIDC sid.
type Proof struct {
	identity        identity
	reference       string
	generation      int64
	loginGeneration int64
	deadline        time.Time
}

// Identity returns a copy of verified claims. Metadata is display-only, never ACL.
func (p Proof) Identity() Identity {
	v := p.identity
	v.Profile = cloneMetadata(v.Profile)
	v.Project = cloneMetadata(v.Project)
	v.AuthHubIdentifiers = cloneCanonicalIdentifiers(v.AuthHubIdentifiers)
	return v
}

func cloneMetadata(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	v := make(map[string]string, len(m))
	for k, s := range m {
		v[k] = s
	}
	return v
}

// SessionReference returns the nonsecret durable browser-session reference.
func (p Proof) SessionReference() string { return p.reference }

// Generation returns the exact durable generation checked for this proof.
func (p Proof) Generation() int64 { return p.generation }

// Deadline returns the fixed minimum of verified freshness and absolute lifetime.
func (p Proof) Deadline() time.Time { return p.deadline }

func (a *app) proof(v session) *Proof {
	if v.Status != sessionActive || v.Proof == nil || v.LoginGeneration <= 0 ||
		!a.now().Before(minTime(v.FreshUntil, v.AbsoluteUntil)) {
		return nil
	}
	p := &Proof{
		loginGeneration: v.LoginGeneration, identity: *v.Proof, reference: v.ID,
		generation: v.Generation, deadline: minTime(v.FreshUntil, v.AbsoluteUntil),
	}
	p.identity.AbsoluteUntil = minTime(p.identity.AbsoluteUntil, v.AbsoluteUntil)
	p.identity.FreshUntil = p.deadline
	p.identity.Profile = cloneMetadata(p.identity.Profile)
	p.identity.Project = cloneMetadata(p.identity.Project)
	p.identity.AuthHubIdentifiers = cloneCanonicalIdentifiers(p.identity.AuthHubIdentifiers)
	return p
}

// View is supplied to application-owned rendering after browser/session checks.
// A nil Proof conveys no authenticated identity, including outage recovery pages.
type View struct {
	CSRF  string
	Proof *Proof
	// CentralLogout is empty unless an explicit central sign-out URL was set.
	// Renderers must omit the link when it is empty. Legacy New retains its route.
	CentralLogout string
}

// Handler serves GET /, POST /login, GET /callback and POST /logout. render owns
// the landing UI, explicit local user resolution and local permissions. Form
// POSTs must carry View.CSRF. Other application routes can call Verify directly.
func (c *Client) Handler(render func(http.ResponseWriter, *http.Request, View)) http.Handler {
	a := *c.app
	if render == nil {
		render = func(w http.ResponseWriter, _ *http.Request, _ View) {
			http.Error(w, "Application renderer required", http.StatusServiceUnavailable)
		}
	}
	a.render = render
	return &a
}

func (a *app) validRequest(r *http.Request) bool {
	u, _ := url.Parse(a.config.Origin)
	return r != nil && u != nil && r.Host == u.Host && len(r.RequestURI) <= 8192 &&
		(r.TLS != nil || a.config.HTTPSReverseProxy || a.config.Ingress.Allows(r))
}

// Verify checks browser binding, trusted ingress and durable validity, renewing
// only through the reviewed single-owner refresh CAS. No cached identity is
// returned on a failed check. Returned proofs have their own fixed deadline.
func (c *Client) Verify(r *http.Request) (Proof, error) {
	a := c.app
	if !a.validRequest(r) {
		return Proof{}, ErrDenied
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		return Proof{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if _, e := browserID(r); e != nil {
		return Proof{}, ErrDenied
	}
	v, e := a.browser(r.WithContext(ctx))
	if e != nil {
		return Proof{}, publicError(e)
	}
	v, e = a.authorize(ctx, v)
	if e != nil {
		return Proof{}, publicError(e)
	}
	p := a.proof(v)
	if p == nil {
		return Proof{}, ErrDenied
	}
	return *p, nil
}

// Valid checks an external session's original proof against current durable
// state. It never refreshes, extends deadlines or resurrects a terminal session.
// Refresh generation changes require a newly admitted proof. Central revocation
// is bounded by the original signed freshness deadline, at most five minutes.
func (c *Client) Valid(ctx context.Context, p Proof) error {
	current, e := c.Check(ctx, p.Binding())
	if e != nil {
		return e
	}
	id := current.identity
	if id.Issuer != p.identity.Issuer || id.ClientID != p.identity.ClientID || id.Subject != p.identity.Subject ||
		id.ProjectID != p.identity.ProjectID || id.SessionID != p.identity.SessionID || id.AuthTime != p.identity.AuthTime {
		return errFenced
	}
	return nil
}

// ReadProtected loads an explicitly supplied Linux protected file with the
// reviewed ownership, mode, size and no-symlink checks. It never prints contents.
func ReadProtected(path string, limit int64) ([]byte, error) { return readProtected(path, limit) }

// ReadClientSecret reads the exact restart-bound maintenance candidate format.
func ReadClientSecret(path, clientID string) (string, error) { return readClientSecret(path, clientID) }

// Binding is persisted inside a protected host-owned external session after
// successful admission. Never accept it from browser form/query/header input.
// The host must preserve the original Deadline unchanged; it is not a TTL.
// LoginGeneration identifies a local login admission, preserved across refresh.
// Zero markers from legacy rows/bindings require a fresh sign-in.
type Binding struct {
	Reference        string    `json:"reference"`
	Generation       int64     `json:"generation"`
	LoginGeneration  int64     `json:"loginGeneration"`
	Deadline         time.Time `json:"deadline"`
	Issuer           string    `json:"issuer"`
	Subject          string    `json:"subject"`
	ProjectID        string    `json:"projectId"`
	ClientID         string    `json:"clientId"`
	CentralSessionID string    `json:"centralSessionId"`
	AuthTime         int64     `json:"authTime"`
	AbsoluteUntil    time.Time `json:"absoluteUntil"`
}

// Binding returns the durable reference, exact generation and immutable deadline.
func (p Proof) Binding() Binding {
	return Binding{
		Reference: p.reference, Generation: p.generation, LoginGeneration: p.loginGeneration, Deadline: p.deadline,
		Issuer: p.identity.Issuer, Subject: p.identity.Subject, ProjectID: p.identity.ProjectID, ClientID: p.identity.ClientID,
		CentralSessionID: p.identity.SessionID, AuthTime: p.identity.AuthTime, AbsoluteUntil: p.identity.AbsoluteUntil,
	}
}

// Check validates a previously admitted host-owned binding after restart without
// network access or refresh. An edited deadline beyond the durable proof cap is
// rejected. The host must also match the returned issuer/subject to its explicit
// local user link and recheck its own ACL; this method grants no local roles.
func (c *Client) Check(ctx context.Context, b Binding) (Proof, error) {
	a := c.app
	if b.Reference == "" || b.Generation <= 0 || !a.now().Before(b.Deadline) {
		return Proof{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, e := a.store.load(ctx, b.Reference)
	if e != nil {
		return Proof{}, publicError(e)
	}
	if v.Status != sessionActive || v.Generation != b.Generation ||
		v.Proof == nil || v.Proof.Issuer != a.config.Issuer || v.Proof.ClientID != a.config.ClientID ||
		!a.config.allowsProject(v.Proof.ProjectID) || b.Deadline.After(minTime(v.FreshUntil, v.AbsoluteUntil)) {
		return Proof{}, ErrDenied
	}
	if !matchesBinding(v, b) {
		return Proof{}, ErrDenied
	}
	if v.RefreshState != refreshReady && v.RefreshState != "uncertain" {
		return Proof{}, ErrUnavailable
	}
	p := a.proof(v)
	if p == nil {
		return Proof{}, ErrDenied
	}
	p.deadline = b.Deadline
	p.identity.FreshUntil = b.Deadline
	return *p, nil
}

// Begin handles the exact POST /login form using the library CSRF/browser state.
func (c *Client) Begin(w http.ResponseWriter, r *http.Request) {
	c.serveEndpoint(w, r, "/login", http.MethodPost)
}

// Callback handles the exact GET /callback. Success installs durable state and
// redirects; admit the local user on a subsequent Verify, never from query data.
func (c *Client) Callback(w http.ResponseWriter, r *http.Request) {
	c.serveEndpoint(w, r, "/callback", http.MethodGet)
}

// Logout handles the exact POST /logout. Local terminal generation commits before
// bounded central revocation. Failed confirmation is not a success acknowledgement;
// the host must still fail closed at its Check/Valid boundary.
// A stale login returns 409 and preserves the newer cookie. Local termination
// with unconfirmed remote revoke/decryption returns 503 and clears the cookie.
// Anonymous/pending logout redirects to /?logout=local-only. The response's
// X-AuthHub-Logout-Scope is binding-revoked, local-only, or unconfirmed; it never
// promises issuer-wide logout. Refresh descendants retain the original intent.
func (c *Client) Logout(w http.ResponseWriter, r *http.Request) {
	c.serveEndpoint(w, r, "/logout", http.MethodPost)
}

func (c *Client) serveEndpoint(w http.ResponseWriter, r *http.Request, path, method string) {
	if r.URL.Path != path || r.Method != method {
		http.NotFound(w, r)
		return
	}
	c.Handler(nil).ServeHTTP(w, r)
}
