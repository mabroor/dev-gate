// Package gitproxy is the credential-injecting git smart-HTTP proxy that dev
// VMs talk to instead of github.com.
//
// A VM authenticates with a per-VM token over HTTP Basic (user ignored,
// password = token) and may reach only its own project's repos. Fetches use a
// read-only installation token; pushes are inspected and forwarded with a
// write token only when every command targets refs/heads/agent/*.
package gitproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/mabroor/dev-gate/internal/pktline"
	"github.com/mabroor/dev-gate/internal/registry"
)

const (
	uploadPack  = "git-upload-pack"
	receivePack = "git-receive-pack"

	// maxUploadBody bounds the want/have negotiation body of a fetch.
	maxUploadBody = 64 << 20
	// maxReceiveBody bounds a push, pack included; the pack is streamed.
	maxReceiveBody = 1 << 30
)

// TokenSource mints GitHub installation tokens scoped to one repo.
type TokenSource interface {
	Token(ctx context.Context, repo string, write bool) (string, error)
}

// forwarded request headers; everything else, notably Authorization, Cookie
// and X-Forwarded-*, is dropped.
var requestHeaders = []string{"Content-Type", "Content-Encoding", "Accept", "Accept-Encoding", "Git-Protocol", "User-Agent"}

// copied back to the client.
var responseHeaders = []string{"Content-Type", "Content-Encoding", "Cache-Control", "Expires", "Pragma"}

type proxy struct {
	reg      *registry.Store
	mint     TokenSource
	upstream *url.URL
	api      *url.URL
	client   *http.Client
}

// Handler serves /<owner>/<repo>[.git]/{info/refs,git-upload-pack,git-receive-pack}
// by proxying to upstream (https://github.com in production).
// It also serves POST /pr (see pr.go).
func Handler(reg *registry.Store, mint TokenSource, upstream *url.URL, opts ...Option) http.Handler {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 0 // receive-pack answers only after the whole pack arrives
	p := &proxy{
		reg:      reg,
		mint:     mint,
		upstream: upstream,
		api:      &url.URL{Scheme: "https", Host: "api.github.com"},
		client: &http.Client{
			Transport: tr,
			// Never follow redirects: a redirect would carry our token elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, err := clientIP(r)
	if err != nil {
		http.Error(w, "bad remote address", http.StatusBadRequest)
		return
	}

	_, token, ok := r.BasicAuth()
	if !ok || token == "" {
		challenge(w)
		return
	}
	entry, ok := p.reg.ByToken(token, ip)
	if !ok {
		if p.reg.HasToken(token) {
			slog.Warn("token used from wrong address", "ip", ip)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		challenge(w)
		return
	}

	if r.URL.Path == "/pr" {
		p.pr(w, r, entry)
		return
	}
	repo, endpoint, ok := parsePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	canonical, ok := matchRepo(entry.Repos, repo)
	if !ok {
		// 404 rather than 403: don't confirm that the repo exists.
		slog.Warn("repo outside project", "project", entry.Project, "repo", repo)
		http.NotFound(w, r)
		return
	}

	switch endpoint {
	case "info/refs":
		p.infoRefs(w, r, entry, canonical)
	case uploadPack, receivePack:
		p.rpc(w, r, entry, canonical, endpoint)
	}
}

// infoRefs proxies the ref advertisement. Upload-pack uses a read token.
// Receive-pack's advertisement lists the same refs, but GitHub refuses it
// unless the token can push, so it needs the write token; no data is written
// until the POST, which is gated below.
func (p *proxy) infoRefs(w http.ResponseWriter, r *http.Request, e registry.Entry, repo string) {
	service := r.URL.Query().Get("service")
	if service != uploadPack && service != receivePack {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	p.forward(w, r, e, repo, "info/refs", "service="+service, nil, service == receivePack)
}

func (p *proxy) rpc(w http.ResponseWriter, r *http.Request, e registry.Entry, repo, service string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if service == uploadPack {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBody)
		p.forward(w, r, e, repo, service, "", r.Body, false)
		return
	}

	// Anything but an identity-encoded body would hide the commands from us.
	// Every Content-Encoding value counts: a second header must not slip past.
	if !identityEncoded(r.Header.Values("Content-Encoding")) {
		http.Error(w, "content-encoding not supported for push", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxReceiveBody)
	refs, replay, err := pktline.CommandRefs(r.Body)
	if err != nil {
		slog.Warn("unparseable push", "project", e.Project, "repo", repo, "err", err)
		http.Error(w, "malformed push request", http.StatusBadRequest)
		return
	}
	if !pktline.AllAgent(refs) {
		slog.Warn("push outside refs/heads/agent/ refused", "project", e.Project, "repo", repo, "refs", len(refs))
		http.Error(w, "pushes are limited to refs/heads/agent/*", http.StatusForbidden)
		return
	}
	p.forward(w, r, e, repo, service, "", replay, true)
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request, e registry.Entry, repo, endpoint, rawQuery string, body io.Reader, write bool) {
	token, err := p.mint.Token(r.Context(), repo, write)
	if err != nil {
		slog.Error("minting token", "project", e.Project, "repo", repo, "write", write, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	u := p.upstream.JoinPath("/" + repo + ".git/" + endpoint)
	u.RawQuery = rawQuery
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if body != nil {
		req.ContentLength = r.ContentLength
	}
	for _, h := range requestHeaders {
		// Push bodies are forwarded as parsed, so no encoding header goes with them.
		if h == "Content-Encoding" && endpoint == receivePack {
			continue
		}
		if v := r.Header.Values(h); len(v) > 0 {
			req.Header[http.CanonicalHeaderKey(h)] = append([]string(nil), v...)
		}
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token)))

	resp, err := p.client.Do(req)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		slog.Error("upstream request", "project", e.Project, "repo", repo, "err", errors.Unwrap(err))
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		slog.Error("upstream redirect refused", "project", e.Project, "repo", repo, "status", resp.StatusCode)
		http.Error(w, "unexpected upstream redirect", http.StatusBadGateway)
		return
	}
	for _, h := range responseHeaders {
		if v := resp.Header.Values(h); len(v) > 0 {
			w.Header()[http.CanonicalHeaderKey(h)] = v
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(flushWriter{w, http.NewResponseController(w)}, resp.Body)
}

// flushWriter flushes after every write so progress and sideband data reach
// git as it arrives.
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	_ = f.rc.Flush()
	return n, err
}

// identityEncoded reports whether the Content-Encoding values, if any, are
// exactly one "identity".
func identityEncoded(values []string) bool {
	switch len(values) {
	case 0:
		return true
	case 1:
		return strings.EqualFold(strings.TrimSpace(values[0]), "identity")
	}
	return false
}

func clientIP(r *http.Request) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="dev-gate"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// parsePath splits /<owner>/<repo>[.git]/<endpoint> and accepts only the three
// smart-HTTP endpoints.
func parsePath(p string) (repo, endpoint string, ok bool) {
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	owner, name, rest := parts[0], strings.TrimSuffix(parts[1], ".git"), parts[2]
	if owner == "" || name == "" {
		return "", "", false
	}
	switch rest {
	case "info/refs", uploadPack, receivePack:
		return owner + "/" + name, rest, true
	}
	return "", "", false
}

// matchRepo finds repo among the project's repos, case-insensitively as GitHub
// does, and returns the registry's spelling so only registered names go upstream.
func matchRepo(repos []string, repo string) (string, bool) {
	for _, r := range repos {
		if strings.EqualFold(r, repo) {
			return r, true
		}
	}
	return "", false
}
