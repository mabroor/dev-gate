package gitproxy

import (
	"context"
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

func (f *fakeMint) CIToken(_ context.Context, repo string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, repo+" ci")
	return "ghs_ci", nil
}

// noCIMint is a TokenSource without CIToken.
type noCIMint struct{}

func (noCIMint) Token(context.Context, string, bool) (string, error) { return "ghs_read", nil }

type route struct {
	status int
	body   string
	loc    string
}

// fakeGitHub serves canned responses by request path and records each request.
type fakeGitHub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	routes map[string]route
	seen   []string
	auth   map[string]string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{routes: map[string]route{}, auth: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.URL.Path)
		f.auth[r.URL.Path] = r.Header.Get("Authorization")
		rt, ok := f.routes[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rt.loc != "" {
			w.Header().Set("Location", f.srv.URL+rt.loc)
		}
		w.WriteHeader(rt.status)
		io.WriteString(w, rt.body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) set(path string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = route{status: status, body: body}
}

func (f *fakeGitHub) redirect(path, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = route{status: http.StatusFound, loc: to}
}

func (f *fakeGitHub) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

const (
	ciRef    = "/repos/acme/widgets/git/ref/heads/agent/fix"
	ciRuns   = "/repos/acme/widgets/actions/runs"
	ciJobs   = "/repos/acme/widgets/actions/runs/11/jobs"
	ciChecks = "/repos/acme/widgets/commits/abc123/check-runs"
	ciLog    = "/repos/acme/widgets/actions/jobs/21/logs"
)

type ciEnv struct {
	*env
	gh *fakeGitHub
}

func newCIEnv(t *testing.T, ciLogs bool, mint TokenSource) *ciEnv {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(registry.Entry{Project: "p", VMIP: netip.MustParseAddr("127.0.0.1"),
		TokenSHA256: sha256.Sum256([]byte(vmToken)), Repos: []string{"acme/widgets"}, CILogs: ciLogs}); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t)
	uu, _ := url.Parse(up.srv.URL)
	gh := newFakeGitHub(t)
	au, _ := url.Parse(gh.srv.URL)
	if mint == nil {
		mint = &fakeMint{}
	}
	srv := httptest.NewServer(Handler(reg, mint, uu, WithAPI(au)))
	t.Cleanup(srv.Close)
	fm, _ := mint.(*fakeMint)
	gh.set(ciRef, 200, `{"object":{"sha":"abc123"}}`)
	gh.set(ciRuns, 200, `{"workflow_runs":[{"id":11,"name":"CI","head_branch":"agent/fix","head_repository":{"full_name":"acme/widgets"},"event":"pull_request","status":"completed","conclusion":"success","html_url":"https://github.com/acme/widgets/actions/runs/11"}]}`)
	gh.set(ciJobs, 200, `{"jobs":[{"id":21,"name":"test","status":"completed","conclusion":"success","html_url":"j21","steps":[{"name":"make test","conclusion":"success"}]}]}`)
	gh.set(ciChecks, 200, `{"check_runs":[{"name":"test","status":"completed","conclusion":"success","app":{"slug":"github-actions"}},{"name":"codecov","status":"completed","conclusion":"success","html_url":"c1","app":{"slug":"codecov"}}]}`)
	return &ciEnv{&env{srv, up, fm}, gh}
}

func (e *ciEnv) get(t *testing.T, query string) (*http.Response, ciResult) {
	t.Helper()
	resp := e.do(t, http.MethodGet, "/ci?"+query, vmToken, nil, nil)
	var res ciResult
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatal(err)
		}
	}
	return resp, res
}

const ciQuery = "repo=acme/widgets&branch=agent/fix"

func TestCISuccessDropsActionsChecks(t *testing.T) {
	e := newCIEnv(t, false, nil)
	resp, res := e.get(t, ciQuery)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if res.State != "success" || res.SHA != "abc123" || len(res.Runs) != 1 || len(res.Runs[0].Jobs) != 1 {
		t.Fatalf("result %+v", res)
	}
	if len(res.Checks) != 1 || res.Checks[0].Name != "codecov" {
		t.Fatalf("checks %+v", res.Checks)
	}
	if res.LogsAvailable {
		t.Fatal("logs_available with ci_logs off")
	}
	if got := e.gh.auth[ciRuns]; got != "Bearer ghs_ci" {
		t.Fatalf("runs auth %q, want the ci token", got)
	}
}

func TestCIFailureWithLogTail(t *testing.T) {
	e := newCIEnv(t, true, nil)
	e.gh.set(ciRuns, 200, `{"workflow_runs":[{"id":11,"name":"CI","head_branch":"agent/fix","head_repository":{"full_name":"acme/widgets"},"event":"push","status":"completed","conclusion":"failure"}]}`)
	e.gh.set(ciJobs, 200, `{"jobs":[{"id":21,"name":"test","status":"completed","conclusion":"failure","steps":[{"name":"checkout","conclusion":"success"},{"name":"make test","conclusion":"failure"}]}]}`)
	e.gh.redirect(ciLog, "/blob/21")
	e.gh.set("/blob/21", 200, strings.Repeat("x", 100<<10)+"BOOM")
	resp, res := e.get(t, ciQuery+"&logs=1")
	if resp.StatusCode != 200 || res.State != "failure" {
		t.Fatalf("status %d result %+v", resp.StatusCode, res)
	}
	job := res.Runs[0].Jobs[0]
	if len(job.FailedSteps) != 1 || job.FailedSteps[0] != "make test" {
		t.Fatalf("failed steps %v", job.FailedSteps)
	}
	if len(job.LogTail) != ciLogTailBytes || !strings.HasSuffix(job.LogTail, "BOOM") {
		t.Fatalf("log tail: %d bytes", len(job.LogTail))
	}
	if a := e.gh.auth["/blob/21"]; a != "" {
		t.Fatalf("token sent to the log redirect target: %q", a)
	}
	if !res.LogsAvailable {
		t.Fatal("logs_available false with ci_logs on")
	}
}

func TestCILogsRefusedWhenDisabled(t *testing.T) {
	e := newCIEnv(t, false, nil)
	resp, _ := e.get(t, ciQuery+"&logs=1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if b, _ := io.ReadAll(resp.Body); !strings.Contains(string(b), "ci logs are disabled") {
		t.Fatalf("body %q", b)
	}
	if n := e.gh.requests(); n != 0 {
		t.Fatalf("%d upstream requests for a refused call", n)
	}
}

func TestCIRefusesBadBranchAndRepo(t *testing.T) {
	e := newCIEnv(t, false, nil)
	for q, want := range map[string]int{
		"repo=acme/widgets&branch=main":            http.StatusForbidden,
		"repo=acme/widgets&branch=agent/../main":   http.StatusForbidden,
		"repo=acme/widgets&branch=":                http.StatusForbidden,
		"repo=acme/other&branch=agent/fix":         http.StatusNotFound,
		"repo=acme/widgets&branch=agent/not-there": http.StatusNotFound,
	} {
		if resp, _ := e.get(t, q); resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", q, resp.StatusCode, want)
		}
	}
}

func TestCIStates(t *testing.T) {
	e := newCIEnv(t, false, nil)
	e.gh.set(ciRuns, 200, `{"workflow_runs":[{"id":11,"name":"CI","head_branch":"agent/fix","head_repository":{"full_name":"acme/widgets"},"event":"push","status":"in_progress"}]}`)
	e.gh.set(ciJobs, 200, `{"jobs":[{"id":21,"name":"test","status":"queued"}]}`)
	if _, res := e.get(t, ciQuery); res.State != "pending" {
		t.Fatalf("state %q, want pending", res.State)
	}
	e2 := newCIEnv(t, false, nil)
	e2.gh.set(ciRuns, 200, `{"workflow_runs":[]}`)
	e2.gh.set(ciChecks, 200, `{"check_runs":[]}`)
	if _, res := e2.get(t, ciQuery); res.State != "none" {
		t.Fatalf("state %q, want none", res.State)
	}
}

func TestCICachesResults(t *testing.T) {
	e := newCIEnv(t, false, nil)
	e.get(t, ciQuery)
	n := e.gh.requests()
	if resp, res := e.get(t, ciQuery); resp.StatusCode != 200 || res.State != "success" {
		t.Fatalf("cached call: %d %+v", resp.StatusCode, res)
	}
	if e.gh.requests() != n {
		t.Fatal("second call within the TTL went upstream")
	}
}

func TestCIUpstreamErrors(t *testing.T) {
	e := newCIEnv(t, false, nil)
	e.gh.set(ciRuns, 404, `{"message":"Resource not accessible by integration"}`)
	if resp, _ := e.get(t, ciQuery); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("runs 404: status %d, want 502", resp.StatusCode)
	}
	e2 := newCIEnv(t, false, nil)
	e2.gh.set(ciChecks, 500, `{}`)
	if resp, _ := e2.get(t, ciQuery); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("checks 500: status %d, want 502", resp.StatusCode)
	}
}

func TestCIAuthMethodAndMinter(t *testing.T) {
	e := newCIEnv(t, false, nil)
	if resp := e.do(t, http.MethodGet, "/ci?"+ciQuery, "", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", resp.StatusCode)
	}
	if resp := e.do(t, http.MethodPost, "/ci?"+ciQuery, vmToken, nil, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
	e2 := newCIEnv(t, false, noCIMint{})
	if resp, _ := e2.get(t, ciQuery); resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("no CIToken: %d, want 501", resp.StatusCode)
	}
}

func TestReadTail(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{{"", 4, ""}, {"abc", 4, "abc"}, {"abcdefgh", 4, "efgh"}, {strings.Repeat("a", 100000) + "end", 3, "end"}} {
		got, err := readTail(strings.NewReader(c.in), c.n)
		if err != nil || got != c.want {
			t.Errorf("readTail(%d bytes, %d) = %q, %v", len(c.in), c.n, got, err)
		}
	}
}

// Review finding 1: runs are looked up by commit, so a VM could point an agent
// branch at main's commit and read main's runs. Only runs of this branch, from
// this repo, for push or pull_request, may come back.
func TestCIOnlyReturnsRunsOfTheAgentBranch(t *testing.T) {
	e := newCIEnv(t, true, nil)
	e.gh.set(ciRuns, 200, `{"workflow_runs":[
		{"id":11,"name":"CI","event":"push","head_branch":"agent/fix","head_repository":{"full_name":"acme/widgets"},"status":"completed","conclusion":"failure"},
		{"id":12,"name":"Deploy","event":"push","head_branch":"main","head_repository":{"full_name":"acme/widgets"},"status":"completed","conclusion":"failure"},
		{"id":13,"name":"Release","event":"workflow_dispatch","head_branch":"agent/fix","head_repository":{"full_name":"acme/widgets"},"status":"completed","conclusion":"failure"},
		{"id":14,"name":"Fork","event":"pull_request","head_branch":"agent/fix","head_repository":{"full_name":"evil/widgets"},"status":"completed","conclusion":"failure"}]}`)
	e.gh.set(ciJobs, 200, `{"jobs":[{"id":21,"name":"test","status":"completed","conclusion":"failure"}]}`)
	e.gh.redirect(ciLog, "/blob/21")
	e.gh.set("/blob/21", 200, "log")
	resp, res := e.get(t, ciQuery+"&logs=1")
	if resp.StatusCode != 200 || len(res.Runs) != 1 || res.Runs[0].Workflow != "CI" {
		t.Fatalf("status %d runs %+v", resp.StatusCode, res.Runs)
	}
	for _, p := range []string{"/repos/acme/widgets/actions/runs/12/jobs", "/repos/acme/widgets/actions/runs/13/jobs", "/repos/acme/widgets/actions/runs/14/jobs"} {
		if _, seen := e.gh.auth[p]; seen {
			t.Errorf("fetched jobs of a foreign run: %s", p)
		}
	}
}

// Review finding 2: a failed log download must not put the signed URL in the
// response.
func TestCILogErrorDoesNotLeakURL(t *testing.T) {
	e := newCIEnv(t, true, nil)
	e.gh.set(ciRuns, 200, `{"workflow_runs":[{"id":11,"name":"CI","event":"push","head_branch":"agent/fix","head_repository":{"full_name":"acme/widgets"},"status":"completed","conclusion":"failure"}]}`)
	e.gh.set(ciJobs, 200, `{"jobs":[{"id":21,"name":"test","status":"completed","conclusion":"failure"}]}`)
	e.gh.redirect(ciLog, "/blob/21?sig=SECRETSIG")
	e.gh.set("/blob/21", 500, "")
	_, res := e.get(t, ciQuery+"&logs=1")
	if tail := res.Runs[0].Jobs[0].LogTail; strings.Contains(tail, "SECRETSIG") || strings.Contains(tail, "/blob/") {
		t.Fatalf("log tail leaks the URL: %q", tail)
	}
}

// Review finding 3: uncached lookups are rate limited per project.
func TestCIRateLimitsUncachedLookups(t *testing.T) {
	e := newCIEnv(t, false, nil)
	limited := false
	for i := 0; i < ciRateBurst+3; i++ {
		resp, _ := e.get(t, "repo=acme/widgets&branch=agent/b"+string(rune('a'+i)))
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("no 429 after the burst")
	}
}

// Review finding 6: dot segments alias another branch.
func TestCIRejectsDotSegments(t *testing.T) {
	e := newCIEnv(t, false, nil)
	for _, b := range []string{"agent/./fix", "agent/fix/.", "agent/fix.", "agent/."} {
		if resp, _ := e.get(t, "repo=acme/widgets&branch="+b); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", b, resp.StatusCode)
		}
	}
}

// Review finding 7: the log is fetched only from GitHub's log hosts.
func TestCILogHostAllowlist(t *testing.T) {
	for host, want := range map[string]bool{
		"productionresultssa1.blob.core.windows.net":     true,
		"pipelines.actions.githubusercontent.com":        true,
		"results-receiver.actions.githubusercontent.com": true,
		"evil.example.com":                               false,
		"10.0.0.1":                                       false,
		"blob.core.windows.net.evil.com":                 false,
	} {
		if got := allowedLogHost(host); got != want {
			t.Errorf("allowedLogHost(%q) = %v, want %v", host, got, want)
		}
	}
}
