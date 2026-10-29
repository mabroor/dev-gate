package gitproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mabroor/dev-gate/internal/registry"
)

const (
	vmToken = "vm-secret-token"
	zero    = "0000000000000000000000000000000000000000"
	sha1    = "1111111111111111111111111111111111111111"
)

type upReq struct {
	Method, Path, RawQuery, Auth, Cookie, ContentType, ContentEncoding string
	Body                                                               []byte
}

type upstream struct {
	srv      *httptest.Server
	mu       sync.Mutex
	reqs     []upReq
	redirect bool
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, upReq{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"),
			r.Header.Get("Cookie"), r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), b})
		redirect := u.redirect
		u.mu.Unlock()
		if redirect {
			http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		fmt.Fprint(w, "upstream-says-hi")
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

type fakeMint struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeMint) Token(_ context.Context, repo string, write bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("%s write=%v", repo, write))
	if write {
		return "ghs_write", nil
	}
	return "ghs_read", nil
}

type env struct {
	proxy *httptest.Server
	up    *upstream
	mint  *fakeMint
}

// newEnv registers a VM at vmIP for project "p" with repo acme/widgets.
func newEnv(t *testing.T, vmIP string) *env {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = reg.Put(registry.Entry{Project: "p", VMIP: netip.MustParseAddr(vmIP),
		TokenSHA256: sha256.Sum256([]byte(vmToken)), Repos: []string{"acme/widgets"}})
	if err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t)
	uu, _ := url.Parse(up.srv.URL)
	mint := &fakeMint{}
	srv := httptest.NewServer(Handler(reg, mint, uu))
	t.Cleanup(srv.Close)
	return &env{srv, up, mint}
}

func (e *env) do(t *testing.T, method, path, token string, body io.Reader, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, e.proxy.URL+path, body)
	if token != "" {
		req.SetBasicAuth("x", token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func pushBody(refs ...string) string {
	var b strings.Builder
	for i, r := range refs {
		line := zero + " " + sha1 + " " + r
		if i == 0 {
			line += "\x00report-status"
		}
		b.WriteString(pkt(line))
	}
	b.WriteString("0000")
	b.WriteString("PACK" + strings.Repeat("x", 100000))
	return b.String()
}

func TestGitProxyRejectsTokenFromOtherIP(t *testing.T) {
	e := newEnv(t, "10.9.9.9") // test client connects from 127.0.0.1
	resp := e.do(t, "GET", "/acme/widgets.git/info/refs?service=git-upload-pack", vmToken, nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if e.up.count() != 0 || len(e.mint.calls) != 0 {
		t.Fatal("request from wrong IP reached the minter or upstream")
	}
}

func TestGitProxyChallengesMissingOrBadAuth(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	for name, token := range map[string]string{"missing": "", "wrong": "nope"} {
		resp := e.do(t, "GET", "/acme/widgets.git/info/refs?service=git-upload-pack", token, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="dev-gate"` {
			t.Errorf("%s: WWW-Authenticate = %q", name, got)
		}
	}
	if e.up.count() != 0 {
		t.Fatal("unauthenticated request reached upstream")
	}
}

func TestGitProxyRejectsRepoOutsideProject(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	for _, p := range []string{
		"/acme/secret.git/info/refs?service=git-upload-pack",
		"/other/widgets.git/info/refs?service=git-upload-pack",
		"/acme/widgets.git/../secret.git/info/refs?service=git-upload-pack",
	} {
		resp := e.do(t, "GET", p, vmToken, nil, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", p, resp.StatusCode)
		}
	}
	if e.up.count() != 0 || len(e.mint.calls) != 0 {
		t.Fatal("outside-project request reached the minter or upstream")
	}
}

func TestGitProxyFetchUsesReadToken(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	resp := e.do(t, "GET", "/acme/widgets.git/info/refs?service=git-upload-pack&junk=1", vmToken, nil,
		map[string]string{"Cookie": "a=b"})
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(got) != "upstream-says-hi" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, got)
	}
	resp = e.do(t, "POST", "/acme/widgets/git-upload-pack", vmToken, strings.NewReader("0032want "+sha1+"\n0000"),
		map[string]string{"Content-Type": "application/x-git-upload-pack-request"})
	if resp.StatusCode != 200 {
		t.Fatalf("upload-pack status = %d", resp.StatusCode)
	}

	for _, c := range e.mint.calls {
		if c != "acme/widgets write=false" {
			t.Errorf("minter call %q, want read token", c)
		}
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_read"))
	if len(e.up.reqs) != 2 {
		t.Fatalf("upstream saw %d requests", len(e.up.reqs))
	}
	for _, r := range e.up.reqs {
		if r.Auth != want {
			t.Errorf("upstream Authorization = %q, want %q", r.Auth, want)
		}
		if r.Cookie != "" {
			t.Error("cookie forwarded upstream")
		}
		if !strings.HasPrefix(r.Path, "/acme/widgets.git/") {
			t.Errorf("upstream path = %q", r.Path)
		}
	}
	if q := e.up.reqs[0].RawQuery; q != "service=git-upload-pack" {
		t.Errorf("upstream query = %q, want only service", q)
	}
	if string(e.up.reqs[1].Body) != "0032want "+sha1+"\n0000" || e.up.reqs[1].ContentType != "application/x-git-upload-pack-request" {
		t.Errorf("upload-pack request not forwarded intact: %+v", e.up.reqs[1])
	}
}

func TestGitProxyPushToMainIs403(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	for _, body := range []string{
		pushBody("refs/heads/main"),
		pushBody("refs/heads/agent/ok", "refs/heads/main"),
		pushBody("refs/tags/agent/x"),
	} {
		resp := e.do(t, "POST", "/acme/widgets.git/git-receive-pack", vmToken, strings.NewReader(body), nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	}
	if e.up.count() != 0 {
		t.Fatal("rejected push sent bytes upstream")
	}
	for _, c := range e.mint.calls {
		if strings.Contains(c, "write=true") {
			t.Fatal("write token minted for rejected push")
		}
	}
}

func TestGitProxyRejectsMalformedAndEncodedPush(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	resp := e.do(t, "POST", "/acme/widgets.git/git-receive-pack", vmToken, strings.NewReader("garbage"), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed: status = %d, want 400", resp.StatusCode)
	}
	resp = e.do(t, "POST", "/acme/widgets.git/git-receive-pack", vmToken, strings.NewReader(pushBody("refs/heads/agent/x")),
		map[string]string{"Content-Encoding": "gzip"})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("gzip: status = %d, want 415", resp.StatusCode)
	}
	if e.up.count() != 0 {
		t.Fatal("bad push reached upstream")
	}
}

func TestGitProxyRejectsDuplicateContentEncodingOnPush(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	req, _ := http.NewRequest("POST", e.proxy.URL+"/acme/widgets.git/git-receive-pack",
		strings.NewReader(pushBody("refs/heads/agent/x")))
	req.SetBasicAuth("x", vmToken)
	req.Header.Add("Content-Encoding", "identity")
	req.Header.Add("Content-Encoding", "deflate")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", resp.StatusCode)
	}
	if e.up.count() != 0 {
		t.Fatal("request reached upstream")
	}
}

func TestGitProxyPushToAgentForwardsWholeBody(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	body := pushBody("refs/heads/agent/feature")
	resp := e.do(t, "POST", "/acme/widgets.git/git-receive-pack", vmToken, bytes.NewReader([]byte(body)),
		map[string]string{"Content-Type": "application/x-git-receive-pack-request"})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(e.up.reqs) != 1 || string(e.up.reqs[0].Body) != body {
		t.Fatalf("upstream body differs (reqs=%d)", len(e.up.reqs))
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_write"))
	if e.up.reqs[0].Auth != want {
		t.Errorf("Authorization = %q", e.up.reqs[0].Auth)
	}
	if e.up.reqs[0].ContentEncoding != "" {
		t.Errorf("Content-Encoding forwarded on push: %q", e.up.reqs[0].ContentEncoding)
	}
	if e.up.reqs[0].ContentType != "application/x-git-receive-pack-request" {
		t.Errorf("content-type = %q", e.up.reqs[0].ContentType)
	}
}

func TestGitProxyReceivePackAdvertisementUsesWriteToken(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	resp := e.do(t, "GET", "/acme/widgets.git/info/refs?service=git-receive-pack", vmToken, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(e.mint.calls) != 1 || e.mint.calls[0] != "acme/widgets write=true" {
		t.Fatalf("minter calls = %v", e.mint.calls)
	}
}

func TestGitProxyDoesNotFollowRedirects(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	e.up.redirect = true
	resp := e.do(t, "GET", "/acme/widgets.git/info/refs?service=git-upload-pack", vmToken, nil, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "" {
		t.Error("upstream Location leaked to client")
	}
	if e.up.count() != 1 {
		t.Fatalf("upstream hits = %d", e.up.count())
	}
}

func TestGitProxyOnlyServesGitEndpoints(t *testing.T) {
	e := newEnv(t, "127.0.0.1")
	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/acme/widgets.git/info/refs", 404},                          // dumb protocol, no service
		{"GET", "/acme/widgets.git/info/refs?service=git-bogus", 404},        //
		{"GET", "/acme/widgets.git/objects/info/packs", 404},                 //
		{"GET", "/acme/widgets.git/git-upload-pack", 405},                    //
		{"POST", "/acme/widgets.git/info/refs?service=git-upload-pack", 405}, //
		{"GET", "/acme/widgets.git", 404},                                    //
		{"GET", "/", 404},                                                    //
	}
	for _, c := range cases {
		resp := e.do(t, c.method, c.path, vmToken, nil, nil)
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, resp.StatusCode, c.want)
		}
	}
	if e.up.count() != 0 {
		t.Fatal("unsupported request reached upstream")
	}
}
