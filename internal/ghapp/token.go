// Package ghapp mints short-lived, repo-scoped GitHub App installation tokens.
package ghapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// refreshMargin is how long before expiry a cached token stops being reused.
	refreshMargin = 10 * time.Minute
	jwtLifetime   = 9 * time.Minute
	jwtBackdate   = time.Minute // tolerate clock skew against GitHub
	maxAPIBody    = 1 << 20
)

// Minter issues installation tokens for one GitHub App.
type Minter struct {
	AppID  string
	Key    *rsa.PrivateKey
	API    *url.URL     // https://api.github.com in production
	Client *http.Client // optional
	Now    func() time.Time

	mu       sync.Mutex
	installs map[string]int64 // "owner/repo" -> installation id
	tokens   map[string]*slot // "owner/repo|read|write"
}

type slot struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

// ParseKey parses a PEM RSA private key in PKCS#1 or PKCS#8 form.
func ParseKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ghapp: no PEM block in key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("ghapp: key is neither PKCS#1 nor PKCS#8")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("ghapp: key is not RSA")
	}
	return rk, nil
}

// Token returns an installation token for repo ("owner/repo"), limited to that
// repo with contents:read, or contents:write plus pull_requests:write when
// write is true. Tokens are cached until 10 minutes before they expire.
func (m *Minter) Token(ctx context.Context, repo string, write bool) (string, error) {
	if write {
		return m.mint(ctx, repo, "write", map[string]string{"contents": "write", "pull_requests": "write"})
	}
	return m.mint(ctx, repo, "read", map[string]string{"contents": "read"})
}

// CIToken returns a token for repo that can read its workflow runs, jobs, job
// logs and check runs, and resolve branches (contents:read). It cannot write.
func (m *Minter) CIToken(ctx context.Context, repo string) (string, error) {
	return m.mint(ctx, repo, "ci", map[string]string{"actions": "read", "checks": "read", "contents": "read"})
}

func (m *Minter) mint(ctx context.Context, repo, kind string, perms map[string]string) (string, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return "", err
	}
	s := m.slot(repo + "|" + kind)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && m.now().Before(s.expires.Add(-refreshMargin)) {
		return s.token, nil
	}

	id, err := m.installation(ctx, owner, name)
	if err != nil {
		return "", err
	}
	var resp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	body := map[string]any{"repositories": []string{name}, "permissions": perms}
	if err := m.call(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", id), body, &resp); err != nil {
		return "", err
	}
	if resp.Token == "" || resp.ExpiresAt.IsZero() {
		return "", errors.New("ghapp: incomplete access token response")
	}
	s.token, s.expires = resp.Token, resp.ExpiresAt
	return s.token, nil
}

func (m *Minter) slot(key string) *slot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokens == nil {
		m.tokens = map[string]*slot{}
	}
	s, ok := m.tokens[key]
	if !ok {
		s = &slot{}
		m.tokens[key] = s
	}
	return s
}

func (m *Minter) installation(ctx context.Context, owner, name string) (int64, error) {
	key := owner + "/" + name
	m.mu.Lock()
	id, ok := m.installs[key]
	m.mu.Unlock()
	if ok {
		return id, nil
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/installation"
	if err := m.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return 0, err
	}
	if resp.ID == 0 {
		return 0, errors.New("ghapp: installation response without id")
	}
	m.mu.Lock()
	if m.installs == nil {
		m.installs = map[string]int64{}
	}
	m.installs[key] = resp.ID
	m.mu.Unlock()
	return resp.ID, nil
}

// call performs an App-authenticated API request. Error messages carry the
// status and path but never the JWT or response tokens.
func (m *Minter) call(ctx context.Context, method, path string, in, out any) error {
	jwt, err := m.jwt()
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := m.API.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ghapp: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxAPIBody))
		return fmt.Errorf("ghapp: %s %s: status %d", method, path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(out)
}

// jwt builds the RS256 App JWT.
func (m *Minter) jwt() (string, error) {
	now := m.now()
	enc := base64.RawURLEncoding
	hdr := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iss": m.AppID,
		"iat": now.Add(-jwtBackdate).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := hdr + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("ghapp: signing JWT: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

func (m *Minter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func splitRepo(repo string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || !validName(owner) || !validName(name) {
		return "", "", fmt.Errorf("ghapp: invalid repo %q", repo)
	}
	return owner, name, nil
}

// ValidRepo reports whether repo is a well-formed "owner/name".
func ValidRepo(repo string) bool {
	_, _, err := splitRepo(repo)
	return err == nil
}

func validName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}
