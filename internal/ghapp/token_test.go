package ghapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeGitHub struct {
	t        *testing.T
	key      *rsa.PublicKey
	srv      *httptest.Server
	mu       sync.Mutex
	now      time.Time
	installs int
	mints    []mintReq
	ttl      time.Duration
}

type mintReq struct {
	Repositories []string          `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
}

func newFakeGitHub(t *testing.T, pub *rsa.PublicKey, now time.Time) *fakeGitHub {
	f := &fakeGitHub{t: t, key: pub, now: now, ttl: time.Hour}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkJWT(r.Header.Get("Authorization")); err != nil {
		f.t.Errorf("bad JWT: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/installation":
		f.installs++
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 4242})
	case r.Method == http.MethodPost && r.URL.Path == "/app/installations/4242/access_tokens":
		var req mintReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mints = append(f.mints, req)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_" + string(rune('a'+len(f.mints))),
			"expires_at": f.now.Add(f.ttl).UTC().Format(time.RFC3339),
		})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) checkJWT(h string) error {
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return context.Canceled
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return context.Canceled
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(f.key, crypto.SHA256, sum[:], sig); err != nil {
		return err
	}
	var hdr struct{ Alg, Typ string }
	b, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(b, &hdr)
	if hdr.Alg != "RS256" {
		return context.Canceled
	}
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	b, _ = base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(b, &claims)
	if claims.Iss != "1234" || claims.Exp-claims.Iat > 600+60 || claims.Exp <= f.now.Unix() || claims.Iat > f.now.Unix() {
		f.t.Errorf("bad claims %+v", claims)
		return context.Canceled
	}
	return nil
}

func setup(t *testing.T) (*Minter, *fakeGitHub, *time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	gh := newFakeGitHub(t, &key.PublicKey, now)
	u, _ := url.Parse(gh.srv.URL)
	clock := &now
	m := &Minter{AppID: "1234", Key: key, API: u, Now: func() time.Time { return *clock }}
	return m, gh, clock
}

func TestMinterRequestsScopedToken(t *testing.T) {
	m, gh, _ := setup(t)
	tok, err := m.Token(context.Background(), "acme/widgets", false)
	if err != nil || tok == "" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	req := gh.mints[0]
	if len(req.Repositories) != 1 || req.Repositories[0] != "widgets" {
		t.Errorf("repositories = %v", req.Repositories)
	}
	if req.Permissions["contents"] != "read" {
		t.Errorf("permissions = %v", req.Permissions)
	}
	if _, err := m.Token(context.Background(), "acme/widgets", true); err != nil {
		t.Fatal(err)
	}
	if p := gh.mints[1].Permissions; p["contents"] != "write" || p["pull_requests"] != "write" || len(p) != 2 {
		t.Errorf("write permissions = %v", p)
	}
}

func TestMinterCachesPerRepoAndPermission(t *testing.T) {
	m, gh, clock := setup(t)
	ctx := context.Background()
	a, _ := m.Token(ctx, "acme/widgets", false)
	b, _ := m.Token(ctx, "acme/widgets", false)
	if a != b || len(gh.mints) != 1 {
		t.Fatalf("expected cache hit: %q %q mints=%d", a, b, len(gh.mints))
	}
	w, _ := m.Token(ctx, "acme/widgets", true)
	if w == a || len(gh.mints) != 2 {
		t.Fatal("write token must not reuse read token")
	}
	*clock = clock.Add(49 * time.Minute) // 11 min left: still cached
	if c, _ := m.Token(ctx, "acme/widgets", false); c != a {
		t.Fatal("expected cached token with 11 minutes left")
	}
	*clock = clock.Add(2 * time.Minute) // 9 min left: refresh
	gh.now = *clock
	c, err := m.Token(ctx, "acme/widgets", false)
	if err != nil || c == a || len(gh.mints) != 3 {
		t.Fatalf("expected refresh within 10 minutes of expiry: c=%q err=%v mints=%d", c, err, len(gh.mints))
	}
	if gh.installs != 1 {
		t.Errorf("installation lookups = %d, want 1 (cached)", gh.installs)
	}
}

func TestMinterRejectsBadRepoAndUnknownInstallation(t *testing.T) {
	m, _, _ := setup(t)
	for _, r := range []string{"", "widgets", "a/b/c", "../x", "acme/"} {
		if _, err := m.Token(context.Background(), r, false); err == nil {
			t.Errorf("repo %q accepted", r)
		}
	}
	if _, err := m.Token(context.Background(), "acme/missing", false); err == nil {
		t.Error("expected error for repo without installation")
	}
}

func TestParseKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for name, in := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		if _, err := ParseKey(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseKey([]byte("nope")); err == nil {
		t.Error("expected error for non-PEM")
	}
}
