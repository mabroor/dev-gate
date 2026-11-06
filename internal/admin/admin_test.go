package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mabroor/dev-gate/internal/gitproxy"
	"github.com/mabroor/dev-gate/internal/registry"
)

const (
	adminTok = "admin-secret"
	vmTok    = "vm-secret"
)

type fakeMint struct{}

func (fakeMint) Token(_ context.Context, _ string, _ bool) (string, error) { return "ghs_x", nil }

type env struct {
	admin, git *httptest.Server
	reg        *registry.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(reg, adminTok)
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	t.Cleanup(up.Close)
	uu, _ := url.Parse(up.URL)
	e := &env{httptest.NewServer(h), httptest.NewServer(gitproxy.Handler(reg, fakeMint{}, uu)), reg}
	t.Cleanup(e.admin.Close)
	t.Cleanup(e.git.Close)
	return e
}

func tokHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func putBody(ip, token string) string {
	return `{"vm_ip":"` + ip + `","token_sha256":"` + tokHash(token) + `","repos":["acme/widgets"],"egress_extra":["example.com"]}`
}

func (e *env) req(t *testing.T, method, path, bearer, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, e.admin.URL+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (e *env) gitInfoRefs(t *testing.T, token string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", e.git.URL+"/acme/widgets.git/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("x", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAdminRequiresBearer(t *testing.T) {
	e := newEnv(t)
	body := putBody("127.0.0.1", vmTok)
	for _, tok := range []string{"", "wrong", adminTok + "x"} {
		if resp := e.req(t, "PUT", "/admin/projects/p", tok, body); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("bearer %q: status = %d, want 401", tok, resp.StatusCode)
		}
	}
	for _, m := range []string{"GET", "DELETE"} {
		path := "/admin/projects"
		if m == "DELETE" {
			path += "/p"
		}
		if resp := e.req(t, m, path, "", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without bearer: %d", m, resp.StatusCode)
		}
	}
	if len(e.reg.List()) != 0 {
		t.Fatal("unauthenticated request changed the registry")
	}
	if resp := e.req(t, "PUT", "/admin/projects/p", adminTok, body); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("with bearer: status = %d, want 204", resp.StatusCode)
	}
}

func TestAdminPutThenGitAuthWorks(t *testing.T) {
	e := newEnv(t)
	if got := e.gitInfoRefs(t, vmTok); got != http.StatusUnauthorized {
		t.Fatalf("before PUT: %d", got)
	}
	if resp := e.req(t, "PUT", "/admin/projects/p", adminTok, putBody("127.0.0.1", vmTok)); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}
	if got := e.gitInfoRefs(t, vmTok); got != http.StatusOK {
		t.Fatalf("after PUT: %d", got)
	}
}

func TestAdminDeleteRevokesImmediately(t *testing.T) {
	e := newEnv(t)
	e.req(t, "PUT", "/admin/projects/p", adminTok, putBody("127.0.0.1", vmTok))
	if got := e.gitInfoRefs(t, vmTok); got != http.StatusOK {
		t.Fatalf("before delete: %d", got)
	}
	if resp := e.req(t, "DELETE", "/admin/projects/p", adminTok, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d", resp.StatusCode)
	}
	if got := e.gitInfoRefs(t, vmTok); got != http.StatusUnauthorized {
		t.Fatalf("after delete: %d", got)
	}
	if resp := e.req(t, "DELETE", "/admin/projects/p", adminTok, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("second DELETE status = %d", resp.StatusCode)
	}
}

func TestAdminPutValidation(t *testing.T) {
	e := newEnv(t)
	h := tokHash(vmTok)
	cases := map[string]struct{ path, body string }{
		"ipv6":           {"/admin/projects/p", `{"vm_ip":"::1","token_sha256":"` + h + `","repos":["a/b"]}`},
		"non-ip":         {"/admin/projects/p", `{"vm_ip":"host","token_sha256":"` + h + `","repos":["a/b"]}`},
		"short hash":     {"/admin/projects/p", `{"vm_ip":"10.0.0.2","token_sha256":"abcd","repos":["a/b"]}`},
		"non-hex hash":   {"/admin/projects/p", `{"vm_ip":"10.0.0.2","token_sha256":"` + strings.Repeat("z", 64) + `","repos":["a/b"]}`},
		"no repos":       {"/admin/projects/p", `{"vm_ip":"10.0.0.2","token_sha256":"` + h + `","repos":[]}`},
		"bad repo":       {"/admin/projects/p", `{"vm_ip":"10.0.0.2","token_sha256":"` + h + `","repos":["nope"]}`},
		"bad egress":     {"/admin/projects/p", `{"vm_ip":"10.0.0.2","token_sha256":"` + h + `","repos":["a/b"],"egress_extra":["*"]}`},
		"bad project":    {"/admin/projects/P", `{"vm_ip":"10.0.0.2","token_sha256":"` + h + `","repos":["a/b"]}`},
		"unknown field":  {"/admin/projects/p", `{"vm_ip":"10.0.0.2","token_sha256":"` + h + `","repos":["a/b"],"x":1}`},
		"malformed json": {"/admin/projects/p", `{`},
	}
	for name, c := range cases {
		if resp := e.req(t, "PUT", c.path, adminTok, c.body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, resp.StatusCode)
		}
	}
	if len(e.reg.List()) != 0 {
		t.Fatal("invalid PUT stored something")
	}
}

func TestAdminPutConflictIs409(t *testing.T) {
	e := newEnv(t)
	e.req(t, "PUT", "/admin/projects/p", adminTok, putBody("10.0.0.2", vmTok))
	if resp := e.req(t, "PUT", "/admin/projects/q", adminTok, putBody("10.0.0.2", "other")); resp.StatusCode != http.StatusConflict {
		t.Fatalf("same ip: %d", resp.StatusCode)
	}
	if resp := e.req(t, "PUT", "/admin/projects/q", adminTok, putBody("10.0.0.3", vmTok)); resp.StatusCode != http.StatusConflict {
		t.Fatalf("same token: %d", resp.StatusCode)
	}
}

func TestAdminGetOmitsHashes(t *testing.T) {
	e := newEnv(t)
	e.req(t, "PUT", "/admin/projects/p", adminTok, putBody("10.0.0.2", vmTok))
	resp := e.req(t, "GET", "/admin/projects", adminTok, "")
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.Contains(string(b), "token") || strings.Contains(string(b), tokHash(vmTok)) {
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil || len(out) != 1 || out[0]["project"] != "p" || out[0]["vm_ip"] != "10.0.0.2" {
		t.Fatalf("body %s err %v", b, err)
	}
}

func TestNewRejectsEmptyToken(t *testing.T) {
	reg, _ := registry.Open(filepath.Join(t.TempDir(), "r.json"))
	if _, err := New(reg, ""); err == nil {
		t.Fatal("empty admin token accepted")
	}
}

func TestAdminPutAndListEgressOpen(t *testing.T) {
	e := newEnv(t)
	body := `{"vm_ip":"10.0.0.2","token_sha256":"` + tokHash(vmTok) + `","repos":["acme/widgets"],"egress_extra":[],"egress_open":true}`
	if resp := e.req(t, "PUT", "/admin/projects/p", adminTok, body); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status %d", resp.StatusCode)
	}
	e.req(t, "PUT", "/admin/projects/q", adminTok, putBody("10.0.0.3", "other"))
	if p, _ := e.reg.ByIP(netip.MustParseAddr("10.0.0.2")); !p.EgressOpen {
		t.Fatal("egress_open not stored")
	}
	resp := e.req(t, "GET", "/admin/projects", adminTok, "")
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out) != 2 {
		t.Fatalf("list: %v %v", out, err)
	}
	if out[0]["egress_open"] != true || out[1]["egress_open"] != false {
		t.Fatalf("list = %v", out)
	}
}

func TestAdminPatchEgressKeepsRegistration(t *testing.T) {
	e := newEnv(t)
	if resp := e.req(t, "PATCH", "/admin/projects/p", adminTok, `{"egress_extra":[]}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("PATCH unknown project: %d, want 404", resp.StatusCode)
	}
	e.req(t, "PUT", "/admin/projects/p", adminTok, putBody("127.0.0.1", vmTok))
	for _, tok := range []string{"", "wrong"} {
		if resp := e.req(t, "PATCH", "/admin/projects/p", tok, `{"egress_extra":[],"egress_open":true}`); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("PATCH bearer %q: %d, want 401", tok, resp.StatusCode)
		}
	}
	for _, bad := range []string{`{"vm_ip":"10.0.0.9"}`, `{"egress_extra":["Bad Host"]}`, `nope`} {
		if resp := e.req(t, "PATCH", "/admin/projects/p", adminTok, bad); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PATCH %s: %d, want 400", bad, resp.StatusCode)
		}
	}
	if resp := e.req(t, "PATCH", "/admin/projects/p", adminTok, `{"egress_extra":["ffmpeg.org"],"egress_open":true,"ci_logs":true}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PATCH: %d, want 204", resp.StatusCode)
	}
	p, _ := e.reg.ByIP(netip.MustParseAddr("127.0.0.1"))
	if !p.EgressOpen || !p.CILogs || len(p.EgressExtra) != 1 || p.EgressExtra[0] != "ffmpeg.org" || len(p.Repos) != 1 {
		t.Fatalf("after PATCH: %+v", p)
	}
	if got := e.gitInfoRefs(t, vmTok); got != http.StatusOK {
		t.Fatalf("git auth after PATCH: %d, want 200", got)
	}
}

func TestAdminPutAndListCILogs(t *testing.T) {
	e := newEnv(t)
	body := `{"vm_ip":"10.0.0.2","token_sha256":"` + tokHash(vmTok) + `","repos":["acme/widgets"],"egress_extra":[],"ci_logs":true}`
	if resp := e.req(t, "PUT", "/admin/projects/p", adminTok, body); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status %d", resp.StatusCode)
	}
	e.req(t, "PUT", "/admin/projects/q", adminTok, putBody("10.0.0.3", "other"))
	resp := e.req(t, "GET", "/admin/projects", adminTok, "")
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out) != 2 {
		t.Fatalf("list: %v %v", out, err)
	}
	if out[0]["ci_logs"] != true || out[1]["ci_logs"] != false {
		t.Fatalf("list = %v", out)
	}
}
