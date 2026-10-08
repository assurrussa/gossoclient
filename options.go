package browser

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/gossoclient/ingress"
)

// Option configures a new client. Use the typed With functions; duplicate
// options, including repeated identical values, and nil options are rejected.
type Option func(*options)

type options struct {
	config config
	inputs Options
	seen   map[string]bool
	err    error
}

func option(name string, apply func(*options)) Option {
	return func(o *options) {
		if o.err != nil {
			return
		}
		if o.seen[name] {
			o.err = fmt.Errorf("duplicate %s option", name)
			return
		}
		o.seen[name] = true
		apply(o)
	}
}

// WithIssuer supplies the exact canonical HTTPS issuer origin.
func WithIssuer(value string) Option {
	return option("issuer", func(o *options) { o.config.Issuer = value })
}

// WithClientID supplies the explicitly registered client identifier.
func WithClientID(value string) Option {
	return option("client ID", func(o *options) { o.config.ClientID = value })
}

// WithProjectID supplies the nonzero canonical project UUID to pin in tokens.
func WithProjectID(value string) Option {
	return option("project ID", func(o *options) { o.config.ProjectID = value })
}

// WithAuthHubClientBoundProject selects the AuthHub immutable-client profile
// instead of an explicit WithProjectID pin. Use only when the configured issuer
// guarantees a client ID belongs permanently to one project and never reuses
// that ID for another project. The project comes solely from a fully verified
// signed ID token and remains pinned in each durable proof, refresh and binding.
// No project is learned from unsigned metadata or cached as a first-login pin.
// This option is not safe for a generic provider without the same guarantee.
func WithAuthHubClientBoundProject() Option {
	return option("project ID", func(o *options) { o.config.ClientBoundProject = true })
}

// WithOrigin supplies the exact application HTTPS origin, distinct from issuer.
func WithOrigin(value string) Option {
	return option("origin", func(o *options) { o.config.Origin = value })
}

// WithCallback supplies the registered callback, exactly origin plus /callback.
func WithCallback(value string) Option {
	return option("callback", func(o *options) { o.config.Callback = value })
}

// WithStore supplies a store constructed by NewPostgresStore. The caller still
// owns its database; constructing a client does not transfer pool ownership.
func WithStore(value *PostgresStore) Option {
	return option("store", func(o *options) { o.inputs.Store = value })
}

// WithClientSecret supplies a protected client secret. It is never logged.
func WithClientSecret(value string) Option {
	return option("client secret", func(o *options) { o.inputs.ClientSecret = value })
}

// WithStorageKey snapshots exactly 32 raw key bytes when this option is created.
// Reusing the option gives each construction a separate copy.
func WithStorageKey(value []byte) Option {
	key := append([]byte(nil), value...)
	return option("storage key", func(o *options) {
		o.inputs.StorageKey = append([]byte(nil), key...)
	})
}

// WithFreshness sets a cap no greater than five minutes. Zero retains that cap.
func WithFreshness(value time.Duration) Option {
	return option("freshness", func(o *options) { o.config.Freshness = value })
}

// WithIssuerCAFile selects bounded public PEM trust roots read at construction.
func WithIssuerCAFile(value string) Option {
	return option("issuer CA file", func(o *options) { o.config.IssuerCAFile = value })
}

// WithIngress selects an immutable verified edge policy. Nil means direct TLS.
func WithIngress(value *ingress.Policy) Option {
	return option("ingress", func(o *options) {
		o.config.Ingress = value
		if value != nil {
			o.config.Transport = privateHTTPTransport
			o.config.ProxyCIDRs = "explicit"
		}
	})
}

// WithHTTPSReverseProxy explicitly delegates incoming transport security to
// the host application's HTTPS-only reverse proxy. The backend HTTP listener
// must not be publicly reachable or accept requests outside that trusted edge.
// This option does not verify network isolation, inspect forwarding headers or
// fabricate TLS state. Exact Host, Origin/CSRF checks and Secure cookies remain
// enforced, and issuer HTTPS verification is unchanged. Do not combine it with
// WithIngress; without either option, requests require direct TLS.
func WithHTTPSReverseProxy() Option {
	return option("ingress", func(o *options) { o.config.HTTPSReverseProxy = true })
}

// WithRevocationEndpoint explicitly pins the revocation URL and takes precedence
// over discovery. Without this option, valid revocation discovery is required.
func WithRevocationEndpoint(value string) Option {
	return option("revocation endpoint", func(o *options) { o.config.RevocationEndpoint = value })
}

// WithCentralLogoutURL sets an optional browser sign-out landing URL. It must
// remain on the issuer origin and conveys no guarantee of issuer-wide logout.
func WithCentralLogoutURL(value string) Option {
	return option("central logout URL", func(o *options) { o.config.CentralLogoutURL = value })
}

func buildOptions(values []Option) (config, Options, error) {
	o := options{seen: make(map[string]bool)}
	for _, value := range values {
		if value == nil {
			return config{}, Options{}, errors.New("nil client option")
		}
		value(&o)
		if o.err != nil {
			return config{}, Options{}, o.err
		}
	}
	for _, name := range []string{
		"issuer", "client ID", "project ID", "origin", "callback",
		"store", "client secret", "storage key",
	} {
		if !o.seen[name] {
			return config{}, Options{}, fmt.Errorf("missing %s option", name)
		}
	}
	// An explicitly empty endpoint is almost always a configuration error.
	// Omit the option to use discovery or to disable the optional landing link.
	if (o.seen["revocation endpoint"] && o.config.RevocationEndpoint == "") ||
		(o.seen["central logout URL"] && o.config.CentralLogoutURL == "") {
		return config{}, Options{}, errors.New("explicit endpoint must not be empty")
	}
	if err := o.config.validate(); err != nil {
		return config{}, Options{}, err
	}
	if err := validateInputs(o.inputs); err != nil {
		return config{}, Options{}, err
	}
	return o.config, o.inputs, nil
}

func validateInputs(o Options) error {
	if o.Store == nil || o.Store.store == nil || o.Store.store.db == nil {
		return errors.New("durable session store required")
	}
	if len(o.StorageKey) != 32 {
		return errors.New("storage key must contain exactly 32 raw bytes")
	}
	if o.ClientSecret == "" || len(o.ClientSecret) > 4096 {
		return errors.New("client secret is required")
	}
	return nil
}

// NewWithOptions validates explicit identity, origin and protected inputs before
// discovery. It uses a supplied or discovered revocation endpoint, never a
// guessed provider route. No central logout link is exposed unless configured.
// Configuration is frozen at construction; only the caller-owned database and
// an immutable ingress policy are shared. Protocol and session fences are the
// same as New; this constructor does not imply general OIDC-provider support.
func NewWithOptions(ctx context.Context, values ...Option) (*Client, error) {
	c, o, err := buildOptions(values)
	if err != nil {
		return nil, err
	}
	return newClient(ctx, c, o)
}
