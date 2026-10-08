# gossoclient

A Go browser-session client using OIDC, PostgreSQL and encrypted refresh-token
storage. It provides verified identity proofs; your application owns local
accounts, identity linking and permissions.

The supported protocol is an **AuthHub-compatible OIDC profile**, not a
general-purpose adapter for every OIDC provider.

Module: `github.com/assurrussa/gossoclient`  
Packages: `browser` at the module root, and `ingress`

```go
import browser "github.com/assurrussa/gossoclient"
```

## Requirements

- Go 1.27.0; the module selects toolchain Go 1.27.1
- An application-owned PostgreSQL database or isolated schema
- A registered confidential OIDC client and project
- Explicit HTTPS issuer, application origin and callback URLs
- A protected client secret and exactly 32 raw storage-key bytes

The caller supplies and owns `*sql.DB`. The client neither opens nor closes the
pool and does not apply migrations automatically. The protected-file
implementation is Linux-oriented; cross-platform support is not advertised.

## Configure the client

Apply `browser.Schema()` through your application's explicit setup or migration
process. Use an isolated PostgreSQL schema and configure every pooled connection
consistently. Do not use the identity provider's database schema.

When sharing the host application's existing pool, use
`NewPostgresStoreWithSchema(ctx, db, "app_sso")`. It borrows that exact
`*sql.DB` and schema-qualifies every session query, including row locks. Schema
names are case-sensitive ASCII identifiers (`[A-Za-z_][A-Za-z0-9_]*`, at most
63 bytes). The old constructor and table names remain unchanged.

Create and migrate the selected schema in the host's normal migration process.
`Schema()` still returns the existing unqualified DDL: apply it on an explicitly
owned transaction with a safely quoted `SET LOCAL search_path` for that schema.
Never issue a session-level `SET search_path` on a shared pool. The SDK does not
create schemas, migrate, open another pool, change pool settings or close the
host's pool. Existing rows can stay in the same schema without a data migration.

After applying the schema:

```go
store, err := browser.NewPostgresStore(ctx, db)
if err != nil {
    return err
}

options := []browser.Option{
    browser.WithIssuer(issuer),
    browser.WithClientID(clientID),
    browser.WithProjectID(projectID),
    browser.WithOrigin(origin),
    browser.WithCallback(origin + "/callback"),
    browser.WithStore(store),
    browser.WithClientSecret(clientSecret),
    browser.WithStorageKey(storageKey),
    browser.WithRevocationEndpoint(revocationURL),
}

if centralLogoutURL != "" {
    options = append(options,
        browser.WithCentralLogoutURL(centralLogoutURL))
}

client, err := browser.NewWithOptions(ctx, options...)
if err != nil {
    return err
}
```

Load secrets from protected application inputs. Do not put them in source, URLs
or logs.

Issuer, client ID, project ID, origin, callback, store, secret and storage key
are required explicitly. Missing, nil, malformed and duplicate options fail
construction. Repeating an identical option also fails.

Issuer and application origin must be canonical HTTPS origins without trailing
slashes and must have different hostnames. Different ports alone do not isolate
browser cookies. Callback must equal the application origin plus `/callback`.
Project ID must be a nonzero canonical UUID.

For an AuthHub issuer that guarantees an immutable client-to-project
registration and never reassigns a retained client ID, replace
`WithProjectID(projectID)` with `WithAuthHubClientBoundProject()`. These options
are mutually exclusive. The exact issuer and client audience remain mandatory;
only a fully verified signed ID token can supply the canonical, nonzero
`project_id`. Every proof and binding retains that project, and refresh,
validity and logout checks preserve its pin. No first-login project cache or
unsigned discovery/profile field supplies authority. Do not select this mode for
a generic provider without the same immutable-registration guarantee.

### Provider endpoints

`WithRevocationEndpoint` selects an explicit URL and takes precedence over
discovery. If omitted, discovery must provide a valid `revocation_endpoint`.
The strict constructor never guesses a provider-specific revocation path.

`WithCentralLogoutURL` supplies an optional browser sign-out landing page. If
omitted, `View.CentralLogout` is empty and your renderer must hide that link.
A landing-page link is not confirmation of issuer-wide logout.

Both URLs must remain on the configured HTTPS issuer origin. Cross-origin URLs,
userinfo, queries, fragments and ambiguous escaped paths are rejected. Backend
HTTP redirects are forbidden, including revocation redirects. Explicitly empty
endpoint options are errors; omit the option instead.

`ValidateConfig` and `ValidateIssuerEndpoint(issuer, endpoint)` support
network-free configuration checks before opening the database or reading
protected inputs. Use `ValidateAuthHubClientConfig` instead of `ValidateConfig`
for the explicit client-bound AuthHub profile; it requires an empty ProjectID.

### Other supported options

- `WithFreshness`: maximum signed-proof freshness, capped at five minutes; zero uses that cap
- `WithIssuerCAFile`: public PEM trust roots for this client, replacing system roots
- `WithIngress`: an immutable, explicitly verified private HTTP ingress policy behind an HTTPS edge; omitted or nil means direct TLS
- `WithHTTPSReverseProxy()`: explicitly use the host application's HTTPS-only reverse proxy, instead of `WithIngress`

`WithHTTPSReverseProxy()` relies on deployment isolation: the backend HTTP
listener must not be published or reachable outside the trusted HTTPS edge, and
the edge must enforce HTTPS for all browser traffic. The SDK cannot verify
those deployment conditions. It does not inspect `Forwarded` or
`X-Forwarded-*`, fabricate `r.TLS`, or use request headers to choose its origin.
Exact configured Host, Origin/CSRF checks and Secure cookies remain enforced.
Outbound issuer TLS and certificate/hostname validation are unchanged; ordinary
publicly trusted HTTPS uses system roots and needs no custom CA file.
The reverse-proxy option and `WithIngress` are mutually exclusive. Omitting both
continues to require direct TLS.

There are no options to disable issuer TLS validation, CSRF protection or
freshness limits, and no arbitrary HTTP-client or transport hooks.

Storage-key bytes are copied when the option is created and again for each
construction. Configuration and the store wrapper are frozen during
construction. The database remains caller-owned and must stay open while the
client is in use.

## HTTP integration

`client.Handler(render)` serves:

- GET `/`: application-owned rendering
- POST `/login`: begin sign-in
- GET `/callback`: consume the OIDC callback
- POST `/logout`: terminate the browser session

The separate `Begin`, `Callback` and `Logout` methods enforce those same
paths and methods. POST forms must include `View.CSRF` and meet the same-origin
checks. Callback success installs durable state and redirects to `/`; it does
not create a local user.

Render `View.CentralLogout` only when nonempty.

Call `Verify(request)` on each protected browser request. Resolve the verified
issuer and subject to an explicitly linked local account, then check your
application's own permissions. Email and profile/project metadata are display
data, not account-linking or authorization evidence.

## Proofs and host sessions

A `Proof` is an immutable snapshot with a fixed deadline. Never convert that
deadline into a rolling local TTL.

For a host-owned session, persist the complete `Proof.Binding()`, including
`LoginGeneration` and the original deadline. Bindings belong in protected
application state, never browser forms, query parameters or headers.

`Check(ctx, binding)` validates that saved binding against durable state without
network access or refresh. It checks the exact generation and identity pins and
cannot extend the original deadline. Refresh requires admission of a newly
verified proof.

Use `errors.Is`:

- `ErrDenied`: expired, terminal, superseded or mismatched authority; require fresh admission
- `ErrUnavailable`: validity could not be confirmed; fail closed without creating or extending authorization

Central revocation is observed at refresh or the existing signed freshness
deadline. `Check` is not online provider introspection. Unknown exchange or
refresh outcomes are not automatically replayed.

## Logout

`RevokeBinding` represents intentional user logout. The host must authenticate
that intent and enforce CSRF protection.

It can end refresh descendants of the same original login, including after
freshness expires. An older binding cannot terminate a distinct newer login.
Native session replacement or cleanup must not call it merely to detach an old
host session.

Local terminal state commits before remote revocation:

- `nil`: local termination and the binding's remote revocation were confirmed
- `ErrRevocationUnconfirmed`: local termination committed, but remote revocation was not confirmed
- `ErrUnavailable`: local termination was not confirmed; no remote revocation follows that uncertain write
- `ErrDenied`: the binding no longer identifies the permitted logout target

None of these results promises issuer-wide logout.

The HTTP `Logout` helper preserves these distinctions through status codes and
the compatibility header `X-AuthHub-Logout-Scope`:

| Result | Response |
| --- | --- |
| Binding revocation confirmed | 303, `binding-revoked`, cookie cleared |
| Anonymous/pending/ended local logout | 303 to `/?logout=local-only`, cookie cleared |
| Local termination confirmed, remote outcome unconfirmed | 503, `local-only`, cookie cleared |
| Local write unconfirmed | 503, `unconfirmed`, cookie preserved |
| Logout superseded by a newer login | 409, `unconfirmed`, newer cookie preserved |

Hosts using `RevokeBinding` directly own their cookie-clearing and response
behavior; the HTTP helper's response contract does not replace that integration.

## Supported provider profile

The client uses `coreos/go-oidc/v3` and `golang.org/x/oauth2`. Its additional
profile requirements remain enforced:

- RS256 ID tokens with the exact issuer and single registered audience
- Authorization code flow with state, nonce and S256 PKCE
- Client-secret Basic authentication
- Same-origin authorization, token, JWKS and selected revocation endpoints
- Required `project_id`, `token_use: "id"`, canonical UUID `sid` and positive `auth_time`
- Optional bounded `authhub_profile` and `authhub_project` metadata
- A new refresh token and verified ID token on successful refresh
- Preserved identity/session pins across refresh, bounded freshness and a seven-day absolute lifetime
- TLS 1.3 for provider connections

Configurable URLs do not remove these requirements or establish interoperability
with another provider.

## Compatibility

The existing `New(ctx, Config, Options)` API remains an AuthHub-profile
compatibility entry point. It retains the relative routes `/oauth2/revoke` and
`/sso/logout`. Prefer `NewWithOptions` for new integrations; its strict
configuration has no such defaults.

Both constructors share the same session implementation. The following formats
are retained for compatibility:

- The `__Host-sso-example` cookie
- Existing `sso_example_*` SQL objects
- Encrypted-state associated-data formats
- Stored identity fields, binding pins and `LoginGeneration`

Renaming these is a data/session migration, not cosmetic cleanup. Legacy rows or
bindings without the login-lineage marker fail closed and require fresh sign-in.

## Testing

Use a disposable PostgreSQL database for `SSO_TEST_DATABASE`. Durable tests create
and remove isolated schemas. Without this setting, those tests skip; a passing
unit-only run does not establish durable-session coverage.

```sh
go test -race ./...
go vet ./...
golangci-lint fmt --diff
golangci-lint run --timeout=3m
```

Test the selected provider profile and your application integration before
deployment. Authentication failures and uncertain storage/network outcomes must
remain fail-closed.

## License

[MIT](LICENSE). Dependencies retain their respective licenses.
