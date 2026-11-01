package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stripe/smokescreen/pkg/smokescreen"

	"github.com/mabroor/dev-gate/internal/registry"
)

// stubResolver sends every name to loopback, where the test origin listens.
type stubResolver struct{}

func (stubResolver) LookupPort(_ context.Context, _, service string) (int, error) {
	return net.LookupPort("tcp", service)
}
func (stubResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if host == "nxdomain.test" {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if host == "private.test" {
		return []net.IP{net.ParseIP("10.1.2.3")}, nil
	}
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

type env struct {
	proxy  *httptest.Server
	origin *httptest.Server
	hits   *atomic.Int32
	logs   *bytes.Buffer
}

// newEnv serves loopback as the allowed destination range, and registers
// project "p" at 127.0.0.1 (extra: extra.test) and "q" at 127.0.0.2
// (extra: other.test). Requests from the test come from 127.0.0.1.
func newEnv(t *testing.T, register bool) *env {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	put := func(project, ip, tok, extra string) {
		if err := reg.Put(registry.Entry{Project: project, VMIP: netip.MustParseAddr(ip),
			TokenSHA256: sha256.Sum256([]byte(tok)), Repos: []string{"a/b"}, EgressExtra: []string{extra}}); err != nil {
			t.Fatal(err)
		}
	}
	put("q", "127.0.0.2", "tq", "other.test")
	if register {
		put("p", "127.0.0.1", "tp", "extra.test")
	}

	hits := &atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "origin-ok")
	}))
	t.Cleanup(origin.Close)

	logs := &bytes.Buffer{}
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	p, err := New(reg, []string{"base.test", "*.wild.test", "private.test", "nxdomain.test"},
		WithLogger(slog.New(slog.NewJSONHandler(logs, nil))),
		WithResolver(stubResolver{}),
		WithAllowRanges([]smokescreen.RuleRange{{Net: *lo}}))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(p.Handler())
	t.Cleanup(proxy.Close)
	t.Cleanup(p.Close)
	return &env{proxy, origin, hits, logs}
}

// get fetches http://<host>:<origin port>/ through the proxy.
func (e *env) get(t *testing.T, host string) (int, string) {
	t.Helper()
	pu, _ := url.Parse(e.proxy.URL)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(e.origin.URL, "http://"))
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
	resp, err := c.Get("http://" + host + ":" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) connect(t *testing.T, host string) int {
	t.Helper()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(e.origin.URL, "http://"))
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

func TestEgressDeniesUnknownIP(t *testing.T) {
	e := newEnv(t, false)
	if code, _ := e.get(t, "base.test"); code != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP from unknown ip: %d", code)
	}
	if code := e.connect(t, "base.test"); code != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT from unknown ip: %d", code)
	}
	if e.hits.Load() != 0 {
		t.Fatal("unknown ip reached the origin")
	}
}

func TestEgressAllowsBasePlusProjectExtra(t *testing.T) {
	e := newEnv(t, true)
	for _, host := range []string{"base.test", "sub.wild.test", "extra.test"} {
		if code, body := e.get(t, host); code != 200 || body != "origin-ok" {
			t.Errorf("HTTP %s: %d %q", host, code, body)
		}
		if code := e.connect(t, host); code != 200 {
			t.Errorf("CONNECT %s: %d", host, code)
		}
	}
}

func TestEgressDeniesOtherProjectsExtra(t *testing.T) {
	e := newEnv(t, true)
	for _, host := range []string{"other.test", "unlisted.test", "wild.test"} {
		if code, _ := e.get(t, host); code != http.StatusProxyAuthRequired {
			t.Errorf("HTTP %s: %d, want 407", host, code)
		}
		if code := e.connect(t, host); code != http.StatusProxyAuthRequired {
			t.Errorf("CONNECT %s: %d, want 407", host, code)
		}
	}
	if e.hits.Load() != 0 {
		t.Fatal("denied host reached the origin")
	}
}

func TestEgressDeniesPrivateAddressesEvenWhenAllowlisted(t *testing.T) {
	e := newEnv(t, true)
	// private.test is allowlisted via the project's extras below, but resolves to 10.x.
	reg, _ := registry.Open(filepath.Join(t.TempDir(), "r2.json"))
	_ = reg.Put(registry.Entry{Project: "p", VMIP: netip.MustParseAddr("127.0.0.1"),
		TokenSHA256: sha256.Sum256([]byte("x")), Repos: []string{"a/b"}, EgressExtra: []string{"private.test"}})
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	p, err := New(reg, nil, WithResolver(stubResolver{}), WithAllowRanges([]smokescreen.RuleRange{{Net: *lo}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	e.proxy = srv
	if code := e.connect(t, "private.test"); code == 200 {
		t.Fatal("proxy tunnelled to a private address")
	}
}

func TestEgressLogsEveryDecision(t *testing.T) {
	e := newEnv(t, true)
	e.get(t, "base.test")
	e.get(t, "unlisted.test")
	type rec struct{ Project, IP, Host, Decision string }
	var got []rec
	for _, line := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		var r rec
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		got = append(got, r)
	}
	want := []rec{{"p", "127.0.0.1", "base.test", "allow"}, {"p", "127.0.0.1", "unlisted.test", "deny"}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("logs = %+v, want %+v", got, want)
	}
}

func TestEgressLogsUnknownIPDenial(t *testing.T) {
	e := newEnv(t, false)
	e.get(t, "base.test")
	var r map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(e.logs.Bytes()), &r); err != nil {
		t.Fatalf("logs %q: %v", e.logs.String(), err)
	}
	if r["decision"] != "deny" || r["ip"] != "127.0.0.1" || r["host"] != "base.test" || r["project"] != "" {
		t.Fatalf("record = %v", r)
	}
}

func TestNewRejectsBadGlobs(t *testing.T) {
	reg, _ := registry.Open(filepath.Join(t.TempDir(), "r.json"))
	for _, g := range []string{"*", "", "a*.com", "https://x.com"} {
		if _, err := New(reg, []string{g}); err == nil {
			t.Errorf("glob %q accepted", g)
		}
	}
}

func TestEgressRefusesClientChosenUpstreamProxy(t *testing.T) {
	e := newEnv(t, true)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(e.origin.URL, "http://"))
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT base.test:%s HTTP/1.1\r\nHost: base.test:%s\r\nX-Upstream-Https-Proxy: https://evil.test:443\r\n\r\n", port, port)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

// decisions parses the JSON decision lines written by the proxy's logger.
func (e *env) decisions(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

func TestEgressLogsFinalOutcomeNotACLVerdict(t *testing.T) {
	// Both names pass the ACL; the connection is then refused (private
	// address) or fails (no DNS answer). The log must say deny, once.
	for _, host := range []string{"private.test", "nxdomain.test"} {
		for _, via := range []string{"http", "connect"} {
			e := newEnv(t, true)
			if via == "http" {
				if code, _ := e.get(t, host); code == 200 {
					t.Fatalf("%s via %s: reached origin", host, via)
				}
			} else if code := e.connect(t, host); code == 200 {
				t.Fatalf("%s via %s: tunnel established", host, via)
			}
			got := e.decisions(t)
			if len(got) != 1 || got[0]["decision"] != "deny" || got[0]["host"] != host ||
				got[0]["project"] != "p" || got[0]["ip"] != "127.0.0.1" {
				t.Errorf("%s via %s: logs = %v", host, via, got)
			}
		}
	}
}

func TestEgressLogsOneAllowLinePerRequest(t *testing.T) {
	e := newEnv(t, true)
	e.get(t, "base.test")
	e.connect(t, "base.test")
	got := e.decisions(t)
	if len(got) != 2 || got[0]["decision"] != "allow" || got[1]["decision"] != "allow" {
		t.Fatalf("logs = %v", got)
	}
}

// newOpenEnv is newEnv's proxy rebuilt with p (127.0.0.1) and q as given:
// openP/openQ set each project's EgressOpen.
func newOpenEnv(t *testing.T, openP, openQ bool) *env {
	t.Helper()
	e := newEnv(t, true)
	reg, err := registry.Open(filepath.Join(t.TempDir(), "open.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		project, ip string
		open        bool
	}{{"p", "127.0.0.1", openP}, {"q", "127.0.0.2", openQ}} {
		if err := reg.Put(registry.Entry{Project: x.project, VMIP: netip.MustParseAddr(x.ip),
			TokenSHA256: sha256.Sum256([]byte(x.project)), Repos: []string{"a/b"}, EgressOpen: x.open}); err != nil {
			t.Fatal(err)
		}
	}
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	p, err := New(reg, []string{"base.test"}, WithResolver(stubResolver{}),
		WithLogger(slog.New(slog.NewJSONHandler(e.logs, nil))),
		WithAllowRanges([]smokescreen.RuleRange{{Net: *lo}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	e.proxy = srv
	return e
}

func TestEgressOpenProjectAllowsAnyPublicHost(t *testing.T) {
	e := newOpenEnv(t, true, false)
	for _, host := range []string{"unlisted.test", "base.test"} {
		if code, body := e.get(t, host); code != 200 || body != "origin-ok" {
			t.Errorf("HTTP %s: %d %q", host, code, body)
		}
		if code := e.connect(t, host); code != 200 {
			t.Errorf("CONNECT %s: %d", host, code)
		}
	}
}

func TestEgressOpenIsPerProject(t *testing.T) {
	// q is open; the requests come from p, which is not.
	e := newOpenEnv(t, false, true)
	if code := e.connect(t, "unlisted.test"); code != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT unlisted.test from a closed project: %d, want 407", code)
	}
}

func TestEgressOpenProjectStillDeniesPrivateAddresses(t *testing.T) {
	e := newOpenEnv(t, true, false)
	if code := e.connect(t, "private.test"); code == 200 {
		t.Fatal("open project tunnelled to a private address")
	}
}

func TestEgressOpenProjectStillRefusesClientChosenUpstreamProxy(t *testing.T) {
	e := newOpenEnv(t, true, false)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(e.origin.URL, "http://"))
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT unlisted.test:%s HTTP/1.1\r\nHost: unlisted.test:%s\r\nX-Upstream-Https-Proxy: https://evil.test:443\r\n\r\n", port, port)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

func TestEgressOpenDecisionsAreLogged(t *testing.T) {
	e := newOpenEnv(t, true, false)
	e.get(t, "unlisted.test")
	for _, d := range e.decisions(t) {
		if d["host"] == "unlisted.test" && d["decision"] == "allow" && d["project"] == "p" {
			return
		}
	}
	t.Fatalf("no allow decision logged for unlisted.test: %s", e.logs.String())
}
