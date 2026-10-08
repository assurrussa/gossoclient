// Package ingress defines the explicit trusted single-host HTTP boundary behind
// a HTTPS edge. It never interprets forwarding or identity headers.
package ingress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// ErrInvalid reports an invalid or unverified private ingress configuration.
var ErrInvalid = errors.New("invalid private ingress configuration")

// Config pins a dedicated local interface and trusted private proxy networks.
// Bind may be a literal loopback or a unique DNS alias resolving to one locally
// assigned private IPv4 address. Host is the exact external HTTPS authority.
// ProxyCIDRs must contain only private or loopback networks, never a wildcard.
type Config struct{ Bind, Host, ProxyCIDRs string }

// Policy is immutable and safe for concurrent requests. Address is the concrete
// verified bind; callers must listen there, never on the original wildcard/alias.
type Policy struct {
	address, host string
	peers         []netip.Prefix
}

// New verifies the interface before any listener opens. No credentials are read.
func New(ctx context.Context, cfg Config) (*Policy, error) {
	host, port, err := net.SplitHostPort(cfg.Bind)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) ||
		cfg.Host == "" || strings.ContainsAny(cfg.Host, "/\\ \r\n\t") {
		return nil, ErrInvalid
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		if host == "" || strings.ContainsAny(host, "/\\ \r\n\t") {
			return nil, ErrInvalid
		}
		ips, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if lookupErr != nil || len(ips) != 1 {
			return nil, ErrInvalid
		}
		ip = ips[0]
	}
	ip = ip.Unmap()
	if !ip.IsLoopback() {
		if !ip.IsPrivate() || !ip.Is4() {
			return nil, ErrInvalid
		}
		addrs, interfaceErr := net.InterfaceAddrs()
		if interfaceErr != nil {
			return nil, ErrInvalid
		}
		local := false
		for _, addr := range addrs {
			prefix, e := netip.ParsePrefix(addr.String())
			if e == nil && prefix.Addr().Unmap() == ip {
				local = true
			}
		}
		if !local {
			return nil, ErrInvalid
		}
	}
	if cfg.ProxyCIDRs == "" || len(cfg.ProxyCIDRs) > 4096 {
		return nil, ErrInvalid
	}
	p := &Policy{address: net.JoinHostPort(ip.String(), port), host: cfg.Host}
	parts := strings.Split(cfg.ProxyCIDRs, ",")
	if len(parts) > 64 {
		return nil, ErrInvalid
	}
	for _, raw := range parts {
		prefix, e := netip.ParsePrefix(raw)
		if e != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || !privatePrefix(prefix) {
			return nil, ErrInvalid
		}
		p.peers = append(p.peers, prefix)
	}
	return p, nil
}

func privatePrefix(p netip.Prefix) bool {
	for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"} {
		bound := netip.MustParsePrefix(raw)
		if bound.Addr().BitLen() == p.Addr().BitLen() && p.Bits() >= bound.Bits() && bound.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Address returns the verified concrete local listener address.
func (p *Policy) Address() string {
	if p == nil {
		return ""
	}
	return p.address
}

// Allows checks the socket peer and exact Host. Forwarded headers cannot grant
// access. A trusted container on the dedicated ingress network is inside this
// boundary; keep applications/database peers off it and publish no backend port.
func (p *Policy) Allows(r *http.Request) bool {
	if p == nil || r == nil || r.TLS != nil || r.Host != p.host {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, e := netip.ParseAddr(host)
	if err != nil || e != nil {
		return false
	}
	for _, prefix := range p.peers {
		if prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
