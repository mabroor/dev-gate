package gitproxy

import (
	"crypto/sha256"
	"encoding/json"
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

type fakeAPI struct {
	srv    *httptest.Server
	mu     sync.Mutex
	paths  []string
	auths  []string
	bodies []map[string]any
	status int
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{status: http.StatusCreated}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.mu.Lock()
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.bodies = append(f.bodies, m)
		st := f.status
		f.mu.Unlock()
		w.WriteHeader(st)
		if st == http.StatusCreated {
			io.WriteString(w, `{"html_url":"https://github.com/acme/widgets/pull/7","number":7}`)
		} else {
			io.WriteString(w, `{"message":"Validation Failed"}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.paths)
}

type prEnv struct {
	*env
	api *fakeAPI
}

func newPREnv(t *testing.T) *prEnv {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(registry.Entry{Project: "p", VMIP: netip.MustParseAddr("127.0.0.1"),
		TokenSHA256: sha256.Sum256([]byte(vmToken)), Repos: []string{"acme/widgets"}}); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t)
	uu, _ := url.Parse(up.srv.URL)
	api := newFakeAPI(t)
	au, _ := url.Parse(api.srv.URL)
	mint := &fakeMint{}
	srv := httptest.NewServer(Handler(reg, mint, uu, WithAPI(au)))
	t.Cleanup(srv.Close)
	return &prEnv{&env{srv, up, mint}, api}
}

func (e *prEnv) post(t *testing.T, token, body string) *http.Response {
	return e.do(t, http.MethodPost, "/pr", token, strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
}

const goodPR = `{"repo":"acme/widgets","head":"agent/fix","base":"main","title":"Fix it","body":"details"}`

func TestPRCreatesDraftWithWriteToken(t *testing.T) {
	e := newPREnv(t)
	resp := e.post(t, vmToken, goodPR)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["url"] != "https://github.com/acme/widgets/pull/7" {
		t.Fatalf("out = %v", out)
	}
	if e.api.paths[0] != "POST /repos/acme/widgets/pulls" || e.api.auths[0] != "Bearer ghs_write" {
		t.Fatalf("api call = %v %v", e.api.paths, e.api.auths)
	}
	b := e.api.bodies[0]
	if b["head"] != "agent/fix" || b["base"] != "main" || b["title"] != "Fix it" || b["draft"] != true {
		t.Fatalf("api body = %v", b)
	}
	if len(e.mint.calls) != 1 || e.mint.calls[0] != "acme/widgets write=true" {
		t.Fatalf("mint calls = %v", e.mint.calls)
	}
}

func TestPRIsAlwaysDraft(t *testing.T) {
	e := newPREnv(t)
	resp := e.post(t, vmToken, `{"repo":"acme/widgets","head":"agent/fix","base":"main","title":"t","draft":false}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if e.api.bodies[0]["draft"] != true {
		t.Fatalf("draft = %v", e.api.bodies[0]["draft"])
	}
}

func TestPRRejectsNonAgentHead(t *testing.T) {
	e := newPREnv(t)
	for _, head := range []string{"main", "feature/x", "agent/", "agent/../main", "other:agent/x", "refs/heads/agent/x", ""} {
		body, _ := json.Marshal(map[string]string{"repo": "acme/widgets", "head": head, "base": "main", "title": "t"})
		resp := e.post(t, vmToken, string(body))
		want := http.StatusForbidden
		if head == "" {
			want = http.StatusBadRequest
		}
		if resp.StatusCode != want {
			t.Errorf("head %q: status = %d, want %d", head, resp.StatusCode, want)
		}
	}
	if e.api.calls() != 0 || len(e.mint.calls) != 0 {
		t.Fatal("rejected PR reached GitHub or minted a token")
	}
}

func TestPRRejectsBadBase(t *testing.T) {
	e := newPREnv(t)
	for _, base := range []string{"", "refs/heads/main", "o:main", "a..b", "/main", "main/", "a b", "x.lock"} {
		body, _ := json.Marshal(map[string]string{"repo": "acme/widgets", "head": "agent/x", "base": base, "title": "t"})
		if resp := e.post(t, vmToken, string(body)); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("base %q: status = %d, want 400", base, resp.StatusCode)
		}
	}
	if e.api.calls() != 0 {
		t.Fatal("rejected PR reached GitHub")
	}
}

func TestPRRepoOutsideProjectIs404(t *testing.T) {
	e := newPREnv(t)
	resp := e.post(t, vmToken, `{"repo":"acme/secret","head":"agent/x","base":"main","title":"t"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if e.api.calls() != 0 {
		t.Fatal("reached GitHub")
	}
}

func TestPRRequiresAuthAndPost(t *testing.T) {
	e := newPREnv(t)
	if resp := e.post(t, "", goodPR); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", resp.StatusCode)
	}
	if resp := e.post(t, "wrong", goodPR); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad auth: %d", resp.StatusCode)
	}
	if resp := e.do(t, http.MethodGet, "/pr", vmToken, nil, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
}

func TestPRRejectsMalformedBody(t *testing.T) {
	e := newPREnv(t)
	for _, body := range []string{`{`, `{"repo":"acme/widgets","head":"agent/x","base":"main"}`, `{"repo":"acme/widgets","head":"agent/x","base":"main","title":"t","extra":1}`} {
		if resp := e.post(t, vmToken, body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestPRMapsGitHubFailures(t *testing.T) {
	e := newPREnv(t)
	e.api.status = http.StatusUnprocessableEntity
	if resp := e.post(t, vmToken, goodPR); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("422 -> %d", resp.StatusCode)
	}
	e.api.status = http.StatusInternalServerError
	if resp := e.post(t, vmToken, goodPR); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("500 -> %d", resp.StatusCode)
	}
}
