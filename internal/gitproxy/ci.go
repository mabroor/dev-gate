package gitproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/mabroor/dev-gate/internal/pktline"
	"github.com/mabroor/dev-gate/internal/registry"
)

// CITokenSource mints a read-only token for a repo's workflow runs, jobs,
// logs and check runs. GET /ci answers 501 when the minter has none.
type CITokenSource interface {
	CIToken(ctx context.Context, repo string) (string, error)
}

const (
	ciCacheTTL     = 15 * time.Second
	ciMaxRuns      = 20
	ciMaxJobs      = 50
	ciMaxLogJobs   = 5
	ciLogTailBytes = 64 << 10
	ciMaxLogBytes  = 64 << 20 // read at most this much of a job log to find its tail
	ciMaxAPIBody   = 4 << 20
)

var errUpstreamNotFound = errors.New("upstream: not found")

type ciJob struct {
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Conclusion  string   `json:"conclusion"`
	URL         string   `json:"url"`
	FailedSteps []string `json:"failed_steps"`
	LogTail     string   `json:"log_tail,omitempty"`
}

type ciRun struct {
	Workflow   string  `json:"workflow"`
	Event      string  `json:"event"`
	Status     string  `json:"status"`
	Conclusion string  `json:"conclusion"`
	URL        string  `json:"url"`
	Jobs       []ciJob `json:"jobs"`
}

type ciCheck struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	URL        string `json:"url"`
}

type ciResult struct {
	Repo          string    `json:"repo"`
	Branch        string    `json:"branch"`
	SHA           string    `json:"sha"`
	State         string    `json:"state"`
	Runs          []ciRun   `json:"runs"`
	Checks        []ciCheck `json:"checks"`
	LogsAvailable bool      `json:"logs_available"`
}

type ciCacheEntry struct {
	expires time.Time
	body    []byte
}

type ciCache struct {
	mu sync.Mutex
	m  map[string]ciCacheEntry
}

func (c *ciCache) get(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || now.After(e.expires) {
		return nil, false
	}
	return e.body, true
}

func (c *ciCache) put(key string, body []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]ciCacheEntry{}
	}
	for k, e := range c.m {
		if now.After(e.expires) {
			delete(c.m, k)
		}
	}
	c.m[key] = ciCacheEntry{now.Add(ciCacheTTL), body}
}

// ci answers GET /ci?repo=&branch=[&logs=1] with the CI state of an agent
// branch. The caller is already authenticated.
func (p *proxy) ci(w http.ResponseWriter, r *http.Request, e registry.Entry) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	q := r.URL.Query()
	repo, ok := matchRepo(e.Repos, q.Get("repo"))
	if !ok {
		slog.Warn("ci: repo outside project", "project", e.Project, "repo", q.Get("repo"))
		http.NotFound(w, r)
		return
	}
	branch := q.Get("branch")
	if !validBranch(branch) || !pktline.AllAgent([]pktline.RefUpdate{{Ref: "refs/heads/" + branch}}) {
		http.Error(w, "branch must be a plain branch name under agent/", http.StatusForbidden)
		return
	}
	logs := q.Get("logs") == "1"
	if logs && !e.CILogs {
		http.Error(w, "ci logs are disabled for this project", http.StatusForbidden)
		return
	}
	mint, ok := p.mint.(CITokenSource)
	if !ok {
		http.Error(w, "ci is not configured", http.StatusNotImplemented)
		return
	}

	key := e.Project + "|" + repo + "|" + branch + "|" + strconv.FormatBool(logs)
	if body, ok := p.ciCache.get(key, time.Now()); ok {
		writeJSON(w, body)
		return
	}
	token, err := mint.CIToken(r.Context(), repo)
	if err != nil {
		slog.Error("ci: minting token", "project", e.Project, "repo", repo, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	res, err := p.ciFetch(r.Context(), token, repo, branch, logs)
	logCI(e.Project, repo, branch, logs, res, err)
	switch {
	case errors.Is(err, errUpstreamNotFound):
		http.Error(w, "branch not found", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	res.LogsAvailable = e.CILogs
	body, _ := json.Marshal(res)
	p.ciCache.put(key, body, time.Now())
	writeJSON(w, body)
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func logCI(project, repo, branch string, logs bool, res *ciResult, err error) {
	if err != nil && !errors.Is(err, errUpstreamNotFound) {
		slog.Error("ci", "project", project, "repo", repo, "branch", branch, "logs", logs, "err", err)
		return
	}
	state := "not_found"
	if res != nil {
		state = res.State
	}
	slog.Info("ci", "project", project, "repo", repo, "branch", branch, "logs", logs, "state", state)
}

func (p *proxy) ciFetch(ctx context.Context, token, repo, branch string, logs bool) (*ciResult, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := p.apiGet(ctx, token, "/repos/"+repo+"/git/ref/heads/"+branch, nil, &ref); err != nil {
		return nil, err
	}
	sha := ref.Object.SHA
	if sha == "" {
		return nil, errors.New("ci: ref has no sha")
	}
	res := &ciResult{Repo: repo, Branch: branch, SHA: sha, Runs: []ciRun{}, Checks: []ciCheck{}}

	var runs struct {
		WorkflowRuns []struct {
			ID         int64  `json:"id"`
			Name       string `json:"name"`
			Event      string `json:"event"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			HTMLURL    string `json:"html_url"`
		} `json:"workflow_runs"`
	}
	if err := p.apiGet(ctx, token, "/repos/"+repo+"/actions/runs",
		url.Values{"head_sha": {sha}, "per_page": {strconv.Itoa(ciMaxRuns)}}, &runs); err != nil {
		return nil, notFoundIsUpstream(err)
	}
	logJobs := 0
	for _, wr := range runs.WorkflowRuns {
		run := ciRun{Workflow: wr.Name, Event: wr.Event, Status: wr.Status, Conclusion: wr.Conclusion, URL: wr.HTMLURL, Jobs: []ciJob{}}
		var jobs struct {
			Jobs []struct {
				ID         int64  `json:"id"`
				Name       string `json:"name"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
				HTMLURL    string `json:"html_url"`
				Steps      []struct {
					Name       string `json:"name"`
					Conclusion string `json:"conclusion"`
				} `json:"steps"`
			} `json:"jobs"`
		}
		if err := p.apiGet(ctx, token, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs", repo, wr.ID),
			url.Values{"per_page": {strconv.Itoa(ciMaxJobs)}}, &jobs); err != nil {
			return nil, notFoundIsUpstream(err)
		}
		for _, j := range jobs.Jobs {
			job := ciJob{Name: j.Name, Status: j.Status, Conclusion: j.Conclusion, URL: j.HTMLURL, FailedSteps: []string{}}
			for _, s := range j.Steps {
				if failed(s.Conclusion) {
					job.FailedSteps = append(job.FailedSteps, s.Name)
				}
			}
			if logs && failed(j.Conclusion) && logJobs < ciMaxLogJobs {
				logJobs++
				tail, err := p.jobLogTail(ctx, token, repo, j.ID)
				if err != nil {
					slog.Warn("ci: job log", "repo", repo, "job", j.ID, "err", err)
					tail = "(log unavailable: " + err.Error() + ")"
				}
				job.LogTail = tail
			}
			run.Jobs = append(run.Jobs, job)
		}
		res.Runs = append(res.Runs, run)
	}

	var checks struct {
		CheckRuns []struct {
			Name       string `json:"name"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			HTMLURL    string `json:"html_url"`
			App        struct {
				Slug string `json:"slug"`
			} `json:"app"`
		} `json:"check_runs"`
	}
	if err := p.apiGet(ctx, token, "/repos/"+repo+"/commits/"+sha+"/check-runs",
		url.Values{"per_page": {"100"}}, &checks); err != nil {
		return nil, notFoundIsUpstream(err)
	}
	for _, c := range checks.CheckRuns {
		if c.App.Slug == "github-actions" {
			continue // already listed as a job
		}
		res.Checks = append(res.Checks, ciCheck{Name: c.Name, Status: c.Status, Conclusion: c.Conclusion, URL: c.HTMLURL})
	}
	res.State = ciState(res)
	return res, nil
}

// notFoundIsUpstream: only the branch lookup may answer 404 to the client.
// A 404 later means the token lacks a permission, which is an upstream fault.
func notFoundIsUpstream(err error) error {
	if errors.Is(err, errUpstreamNotFound) {
		return errors.New("ci: upstream 404 (missing App permission?)")
	}
	return err
}

func failed(conclusion string) bool {
	switch conclusion {
	case "failure", "timed_out", "cancelled", "action_required", "startup_failure":
		return true
	}
	return false
}

func ciState(res *ciResult) string {
	if len(res.Runs) == 0 && len(res.Checks) == 0 {
		return "none"
	}
	pending, bad := false, false
	note := func(status, conclusion string) {
		if status != "completed" {
			pending = true
		} else if failed(conclusion) {
			bad = true
		}
	}
	for _, r := range res.Runs {
		note(r.Status, r.Conclusion)
		for _, j := range r.Jobs {
			note(j.Status, j.Conclusion)
		}
	}
	for _, c := range res.Checks {
		note(c.Status, c.Conclusion)
	}
	switch {
	case pending:
		return "pending"
	case bad:
		return "failure"
	}
	return "success"
}

func (p *proxy) apiGet(ctx context.Context, token, path string, q url.Values, v any) error {
	u := p.api.JoinPath(path)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	setAPIHeaders(req, token)
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errUpstreamNotFound
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("ci: GET %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, ciMaxAPIBody)).Decode(v)
}

func setAPIHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "dev-gate")
}

// jobLogTail fetches a job's log and returns its last ciLogTailBytes. GitHub
// answers with a redirect to a signed URL; that request goes without our token,
// and the URL is never shown to the VM.
func (p *proxy) jobLogTail(ctx context.Context, token, repo string, job int64) (string, error) {
	u := p.api.JoinPath(fmt.Sprintf("/repos/%s/actions/jobs/%d/logs", repo, job))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	setAPIHeaders(req, token)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Host == "" || (loc.Scheme != "https" && loc.Scheme != p.api.Scheme) {
		return "", errors.New("bad log redirect")
	}
	lreq, err := http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil)
	if err != nil {
		return "", err
	}
	lreq.Header.Set("User-Agent", "dev-gate")
	lresp, err := p.client.Do(lreq)
	if err != nil {
		return "", err
	}
	defer lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("log download status %d", lresp.StatusCode)
	}
	return readTail(io.LimitReader(lresp.Body, ciMaxLogBytes), ciLogTailBytes)
}

// readTail returns the last n bytes of r.
func readTail(r io.Reader, n int) (string, error) {
	buf := make([]byte, 0, 2*n)
	chunk := make([]byte, 32<<10)
	for {
		k, err := r.Read(chunk)
		buf = append(buf, chunk[:k]...)
		if len(buf) > 2*n {
			buf = append(buf[:0], buf[len(buf)-n:]...)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if len(buf) > n {
		buf = buf[len(buf)-n:]
	}
	return string(buf), nil
}
