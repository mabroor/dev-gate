package gitproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/mabroor/dev-gate/internal/pktline"
	"github.com/mabroor/dev-gate/internal/registry"
)

const (
	maxPRRequest  = 128 << 10
	maxPRResponse = 1 << 20
	maxTitleBytes = 256
	maxBodyBytes  = 64 << 10
)

// Option configures Handler.
type Option func(*proxy)

// WithAPI sets the GitHub REST API base URL used by POST /pr; the default is
// https://api.github.com.
func WithAPI(u *url.URL) Option { return func(p *proxy) { p.api = u } }

type prRequest struct {
	Repo  string `json:"repo"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Title string `json:"title"`
	Body  string `json:"body"`
	// Draft is accepted and ignored: PRs are always drafts.
	Draft *bool `json:"draft"`
}

// pr opens a draft pull request from an agent branch. The caller is already
// authenticated; the client cannot influence draft, maintainer_can_modify or
// any other field of the upstream request.
func (p *proxy) pr(w http.ResponseWriter, r *http.Request, e registry.Entry) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPRRequest)
	var in prRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	repo, ok := matchRepo(e.Repos, in.Repo)
	if !ok {
		slog.Warn("pr: repo outside project", "project", e.Project, "repo", in.Repo)
		http.NotFound(w, r)
		return
	}
	if in.Head == "" || in.Title == "" || len(in.Title) > maxTitleBytes || len(in.Body) > maxBodyBytes {
		http.Error(w, "head and title are required; title or body too long", http.StatusBadRequest)
		return
	}
	if !pktline.AllAgent([]pktline.RefUpdate{{Ref: "refs/heads/" + in.Head}}) {
		slog.Warn("pr: head outside agent/ refused", "project", e.Project, "repo", repo)
		http.Error(w, "head must be a branch under agent/", http.StatusForbidden)
		return
	}
	if !validBranch(in.Head) || !validBranch(in.Base) || strings.HasPrefix(in.Base, "refs/") {
		http.Error(w, "head and base must be plain branch names", http.StatusBadRequest)
		return
	}

	token, err := p.mint.Token(r.Context(), repo, true)
	if err != nil {
		slog.Error("pr: minting token", "project", e.Project, "repo", repo, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"title": in.Title, "head": in.Head, "base": in.Base, "body": in.Body, "draft": true,
	})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		p.api.JoinPath("/repos/"+repo+"/pulls").String(), bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "dev-gate")

	resp, err := p.client.Do(req)
	if err != nil {
		slog.Error("pr: upstream request", "project", e.Project, "repo", repo, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxPRResponse))

	switch {
	case resp.StatusCode == http.StatusCreated:
		var out struct {
			HTMLURL string `json:"html_url"`
		}
		if json.Unmarshal(raw, &out) != nil || out.HTMLURL == "" {
			http.Error(w, "unexpected upstream response", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"url": out.HTMLURL})
	case resp.StatusCode == http.StatusUnprocessableEntity:
		// Usually "a pull request already exists" or "no commits between".
		slog.Info("pr: rejected by github", "project", e.Project, "repo", repo)
		http.Error(w, "pull request rejected by GitHub (validation failed)", http.StatusUnprocessableEntity)
	default:
		slog.Error("pr: unexpected upstream status", "project", e.Project, "repo", repo, "status", resp.StatusCode)
		http.Error(w, "upstream error", http.StatusBadGateway)
	}
}

// validBranch accepts a conservative subset of git branch names.
func validBranch(s string) bool {
	if s == "" || len(s) > 200 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") ||
		strings.HasPrefix(s, "-") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".lock") ||
		strings.Contains(s, "..") || strings.Contains(s, "//") {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '/':
		default:
			return false
		}
	}
	return true
}
