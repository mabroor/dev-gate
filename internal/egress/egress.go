// Package egress is the forward proxy dev VMs use to reach the internet. It
// wraps Smokescreen: each request's role is the project registered for the
// source IP, and the ACL is the base allowlist plus that project's extras.
// Smokescreen's refusal to connect to private, loopback and link-local
// addresses stays on, so a VM cannot use the proxy to reach Lab hosts.
package egress

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	"github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"

	"github.com/mabroor/dev-gate/internal/registry"
)

const idleTimeout = 5 * time.Minute

type options struct {
	log         *slog.Logger
	resolver    smokescreen.Resolver
	allowRanges []smokescreen.RuleRange
	port        uint16
}

// Option customises New; the exported ones exist for tests.
type Option func(*options)

func WithLogger(l *slog.Logger) Option           { return func(o *options) { o.log = l } }
func WithResolver(r smokescreen.Resolver) Option { return func(o *options) { o.resolver = r } }

// WithAllowRanges exempts address ranges from Smokescreen's private-range block.
func WithAllowRanges(r []smokescreen.RuleRange) Option {
	return func(o *options) { o.allowRanges = r }
}

// WithPort tells the proxy which port it listens on, so it can refuse to be
// used to connect to itself.
func WithPort(p uint16) Option { return func(o *options) { o.port = p } }

// Proxy is the egress proxy.
type Proxy struct {
	cfg   *smokescreen.Config
	proxy http.Handler
}

// New builds a proxy whose ACL is base plus each project's EgressExtra,
// default deny, read from reg on every decision so admin changes apply at once.
func New(reg *registry.Store, base []string, opts ...Option) (*Proxy, error) {
	o := options{log: slog.Default()}
	for _, f := range opts {
		f(&o)
	}
	checker := &acl.ACL{}
	for _, g := range base {
		if err := checker.ValidateDomainGlob("base allowlist", g); err != nil {
			return nil, err
		}
	}

	d := &decider{reg: reg, base: slices.Clone(base)}
	cfg := smokescreen.NewConfig()
	cfg.Log.SetFormatter(&logrus.JSONFormatter{})
	cfg.Log.AddHook(counterHook{})
	cfg.Log.AddHook(decisionHook{o.log})
	cfg.EgressACL = d
	cfg.RoleFromRequest = d.role
	cfg.IdleTimeout = idleTimeout
	if o.resolver != nil {
		cfg.Resolver = o.resolver
	}
	cfg.AllowRanges = o.allowRanges
	if o.port != 0 {
		cfg.Port = o.port
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.InitializeSelfConnectionDetection(); err != nil {
		o.log.Warn("egress: self-connection detection unavailable", "err", err)
	}
	cfg.ShuttingDown.Store(false)
	cfg.ConnTracker = conntrack.NewTracker(cfg.IdleTimeout, cfg.MetricsClient, cfg.Log, cfg.ShuttingDown, nil)
	return &Proxy{cfg: cfg, proxy: smokescreen.BuildProxy(cfg)}, nil
}

// Handler serves CONNECT and plain HTTP proxy requests.
func (p *Proxy) Handler() http.Handler { return p.proxy }

// Close stops accepting new tunnels and drops the established ones. Smokescreen's
// own StartWithConfig is not used because it installs a SIGHUP handler that
// shuts the proxy down, and dev-gate uses SIGHUP to reload the registry.
func (p *Proxy) Close() {
	p.cfg.ShuttingDown.Store(true)
	p.cfg.ConnTracker.Range(func(k, _ any) bool {
		if c, ok := k.(*conntrack.InstrumentedConn); ok {
			c.Close()
		}
		return true
	})
}

// counterHook snapshots the *uint64 byte counters that Smokescreen v0.1.0
// puts in its connection-close log fields. Its formatter would otherwise read
// them non-atomically while the tunnel's copy goroutines are still adding to
// them, which the race detector reports.
type counterHook struct{}

func (counterHook) Levels() []logrus.Level { return logrus.AllLevels }

func (counterHook) Fire(e *logrus.Entry) error {
	for k, v := range e.Data {
		if c, ok := v.(*uint64); ok && c != nil {
			e.Data[k] = atomic.LoadUint64(c)
		}
	}
	return nil
}

// decisionHook emits our one decision line per request from Smokescreen's
// CANONICAL-PROXY-DECISION entry. That entry is written after the ACL check,
// DNS resolution and the private-range check, so it carries the final outcome:
// a request the ACL allowed but whose dial was refused or failed is a deny.
type decisionHook struct{ log *slog.Logger }

func (decisionHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h decisionHook) Fire(e *logrus.Entry) error {
	if e.Message != smokescreen.CanonicalProxyDecision {
		return nil
	}
	allowed, _ := e.Data[smokescreen.LogFieldAllow].(bool)
	_, failed := e.Data[smokescreen.LogFieldError]
	project, _ := e.Data[smokescreen.LogFieldProject].(string)
	remote, _ := e.Data[smokescreen.LogFieldInRemoteAddr].(string)
	host, _ := e.Data[smokescreen.LogFieldRequestedHost].(string)
	ip := remote
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		ip = ap.Addr().Unmap().String()
	}
	record(h.log, project, ip, host, allowed && !failed)
	return nil
}

type decider struct {
	reg  *registry.Store
	base []string
}

// role maps the source address to the project registered for it. An unknown
// address has no role, which Smokescreen turns into a denial.
func (d *decider) role(r *http.Request) (string, error) {
	ip, err := sourceIP(r)
	if err == nil {
		if e, ok := d.reg.ByIP(ip); ok {
			return e.Project, nil
		}
	}
	return "", errors.New("egress: source address is not a registered dev VM")
}

// Decide allows host if it is on the base list or the caller's project list.
func (d *decider) Decide(a acl.DecideArgs) (acl.Decision, error) {
	deny := func(project, why string) (acl.Decision, error) {
		return acl.Decision{Result: acl.Deny, Reason: why, Project: project}, nil
	}
	ip, err := sourceIP(a.Req)
	if err != nil {
		return deny("", "bad source address")
	}
	// Re-resolve rather than trust the role, so a registry change between the
	// two lookups cannot apply one project's rule to another's VM.
	e, ok := d.reg.ByIP(ip)
	if !ok || e.Project != a.Service {
		return deny("", "source address is not a registered dev VM")
	}
	rule := acl.Rule{
		Project:     e.Project,
		Policy:      acl.Enforce,
		DomainGlobs: append(slices.Clone(d.base), e.EgressExtra...),
	}
	res, err := (&acl.ACL{Rules: map[string]acl.Rule{e.Project: rule}}).Decide(acl.DecideArgs{
		Req: a.Req, Service: e.Project, Host: a.Host,
		// A client-chosen upstream proxy must be refused: the rule lists none.
		ConnectProxyHost: a.ConnectProxyHost,
	})
	if err != nil {
		return deny(e.Project, "acl error")
	}
	return res, nil
}

func record(log *slog.Logger, project, ip, host string, allow bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	decision := "deny"
	if allow {
		decision = "allow"
	}
	log.Info("egress", "project", project, "ip", ip, "host", host, "decision", decision)
}

func sourceIP(r *http.Request) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("egress: remote address %q: %w", r.RemoteAddr, err)
	}
	return ap.Addr().Unmap(), nil
}
