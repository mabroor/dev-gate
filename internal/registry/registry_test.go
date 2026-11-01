package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func entry(project, ip, token string, repos ...string) Entry {
	return Entry{
		Project:     project,
		VMIP:        netip.MustParseAddr(ip),
		TokenSHA256: sha256.Sum256([]byte(token)),
		Repos:       repos,
		EgressExtra: []string{"example.com"},
	}
}

func open(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestRegistryByTokenRequiresMatchingIP(t *testing.T) {
	s, _ := open(t)
	if err := s.Put(entry("p", "192.168.5.10", "tok", "o/r")); err != nil {
		t.Fatal(err)
	}
	if e, ok := s.ByToken("tok", netip.MustParseAddr("192.168.5.10")); !ok || e.Project != "p" {
		t.Fatalf("matching token+ip: ok=%v e=%+v", ok, e)
	}
	if _, ok := s.ByToken("tok", netip.MustParseAddr("192.168.5.11")); ok {
		t.Fatal("token accepted from wrong IP")
	}
	if _, ok := s.ByToken("other", netip.MustParseAddr("192.168.5.10")); ok {
		t.Fatal("wrong token accepted")
	}
	if _, ok := s.ByToken("", netip.MustParseAddr("192.168.5.10")); ok {
		t.Fatal("empty token accepted")
	}
	if !s.HasToken("tok") || s.HasToken("other") {
		t.Fatal("HasToken wrong")
	}
}

func TestRegistryByTokenUnmapsIPv4In6(t *testing.T) {
	s, _ := open(t)
	_ = s.Put(entry("p", "192.168.5.10", "tok", "o/r"))
	if _, ok := s.ByToken("tok", netip.MustParseAddr("::ffff:192.168.5.10")); !ok {
		t.Fatal("4in6 address not matched")
	}
}

func TestRegistryByIPAndDelete(t *testing.T) {
	s, _ := open(t)
	_ = s.Put(entry("p", "192.168.5.10", "tok", "o/r"))
	if e, ok := s.ByIP(netip.MustParseAddr("192.168.5.10")); !ok || e.Project != "p" {
		t.Fatal("ByIP miss")
	}
	if err := s.Delete("p"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ByIP(netip.MustParseAddr("192.168.5.10")); ok {
		t.Fatal("entry survived delete")
	}
	if _, ok := s.ByToken("tok", netip.MustParseAddr("192.168.5.10")); ok {
		t.Fatal("token survived delete")
	}
}

func TestRegistryPutReplacesProjectAndRejectsIPConflict(t *testing.T) {
	s, _ := open(t)
	_ = s.Put(entry("p", "192.168.5.10", "old", "o/r"))
	if err := s.Put(entry("p", "192.168.5.10", "new", "o/r")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ByToken("old", netip.MustParseAddr("192.168.5.10")); ok {
		t.Fatal("old token still valid after rotation")
	}
	if err := s.Put(entry("q", "192.168.5.10", "t2", "o/q")); err == nil {
		t.Fatal("expected conflict for IP owned by another project")
	}
	if err := s.Put(Entry{Project: "z"}); err == nil {
		t.Fatal("expected error for invalid entry")
	}
}

func TestRegistryPersistsAndReloads(t *testing.T) {
	s, path := open(t)
	if err := s.Put(entry("p", "192.168.5.10", "tok", "o/r", "o/s")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := s2.ByToken("tok", netip.MustParseAddr("192.168.5.10"))
	if !ok || len(e.Repos) != 2 || e.EgressExtra[0] != "example.com" {
		t.Fatalf("reload: ok=%v e=%+v", ok, e)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestOpenMissingFileIsEmptyAndCorruptFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(filepath.Join(dir, "none.json")); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o600)
	if _, err := Open(bad); err == nil {
		t.Fatal("expected error for corrupt registry")
	}
}

func TestReturnedEntriesAreCopies(t *testing.T) {
	s, _ := open(t)
	_ = s.Put(entry("p", "192.168.5.10", "tok", "o/r"))
	e, _ := s.ByIP(netip.MustParseAddr("192.168.5.10"))
	e.Repos[0] = "evil/repo"
	e2, _ := s.ByIP(netip.MustParseAddr("192.168.5.10"))
	if e2.Repos[0] != "o/r" {
		t.Fatal("store state mutated through returned entry")
	}
}

func TestPutRejectsMalformedEntries(t *testing.T) {
	s, _ := open(t)
	bad := map[string]Entry{
		"repo without owner":   entry("p", "192.168.5.10", "t", "justname"),
		"repo with extra":      entry("p", "192.168.5.10", "t", "o/r/x"),
		"repo with space":      entry("p", "192.168.5.10", "t", "o/r r"),
		"repo dot-dot":         entry("p", "192.168.5.10", "t", "o/.."),
		"project uppercase":    entry("P", "192.168.5.10", "t", "o/r"),
		"project with slash":   entry("a/b", "192.168.5.10", "t", "o/r"),
		"project leading dash": entry("-a", "192.168.5.10", "t", "o/r"),
		"bad egress host":      {Project: "p", VMIP: netip.MustParseAddr("192.168.5.10"), Repos: []string{"o/r"}, EgressExtra: []string{"*"}},
		"egress with scheme":   {Project: "p", VMIP: netip.MustParseAddr("192.168.5.10"), Repos: []string{"o/r"}, EgressExtra: []string{"https://x.com"}},
	}
	for name, e := range bad {
		if err := s.Put(e); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("rejected entries were stored")
	}
}

func TestPutRejectsTokenHashUsedByAnotherProject(t *testing.T) {
	s, _ := open(t)
	if err := s.Put(entry("p", "192.168.5.10", "same", "o/r")); err != nil {
		t.Fatal(err)
	}
	err := s.Put(entry("q", "192.168.5.11", "same", "o/q"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if err := s.Put(entry("p", "192.168.5.10", "same", "o/r")); err != nil {
		t.Fatalf("re-put of same project: %v", err)
	}
}

func TestPutIPConflictIsErrConflict(t *testing.T) {
	s, _ := open(t)
	_ = s.Put(entry("p", "192.168.5.10", "a", "o/r"))
	if err := s.Put(entry("q", "192.168.5.10", "b", "o/q")); !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestOpenRejectsInvalidAndDuplicateEntries(t *testing.T) {
	dir := t.TempDir()
	h1 := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("a")); return s[:] }())
	h2 := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("b")); return s[:] }())
	cases := map[string]string{
		"duplicate project": `[{"project":"p","vm_ip":"192.168.5.10","token_sha256":"` + h1 + `","repos":["o/r"]},
			{"project":"p","vm_ip":"192.168.5.11","token_sha256":"` + h2 + `","repos":["o/r"]}]`,
		"duplicate ip": `[{"project":"p","vm_ip":"192.168.5.10","token_sha256":"` + h1 + `","repos":["o/r"]},
			{"project":"q","vm_ip":"192.168.5.10","token_sha256":"` + h2 + `","repos":["o/r"]}]`,
		"duplicate token": `[{"project":"p","vm_ip":"192.168.5.10","token_sha256":"` + h1 + `","repos":["o/r"]},
			{"project":"q","vm_ip":"192.168.5.11","token_sha256":"` + h1 + `","repos":["o/r"]}]`,
		"bad repo": `[{"project":"p","vm_ip":"192.168.5.10","token_sha256":"` + h1 + `","repos":["nope"]}]`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		_ = os.WriteFile(path, []byte(body), 0o600)
		if _, err := Open(path); err == nil {
			t.Errorf("%s: Open succeeded", name)
		}
	}
}

func TestListOmitsNothingButIsSortedAndCopied(t *testing.T) {
	s, _ := open(t)
	_ = s.Put(entry("b", "192.168.5.11", "b", "o/b"))
	_ = s.Put(entry("a", "192.168.5.10", "a", "o/a"))
	l := s.List()
	if len(l) != 2 || l[0].Project != "a" || l[1].Project != "b" {
		t.Fatalf("List = %+v", l)
	}
	l[0].Repos[0] = "evil/x"
	if s.List()[0].Repos[0] != "o/a" {
		t.Fatal("List leaked internal slice")
	}
}

func TestReloadPicksUpEditsAndKeepsStateOnError(t *testing.T) {
	s, path := open(t)
	_ = s.Put(entry("p", "192.168.5.10", "a", "o/r"))
	other, _ := Open(path)
	_ = other.Put(entry("q", "192.168.5.11", "b", "o/q"))
	if _, ok := s.ByIP(netip.MustParseAddr("192.168.5.11")); ok {
		t.Fatal("saw q before reload")
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ByIP(netip.MustParseAddr("192.168.5.11")); !ok {
		t.Fatal("q missing after reload")
	}
	_ = os.WriteFile(path, []byte("{broken"), 0o600)
	if err := s.Reload(); err == nil {
		t.Fatal("reload of corrupt file succeeded")
	}
	if len(s.List()) != 2 {
		t.Fatal("state lost after failed reload")
	}
}

// A Delete that lands between Reload's read and its swap must not be undone by
// the stale snapshot: a revoked project would come back.
func TestReloadDoesNotLoseConcurrentDelete(t *testing.T) {
	s, path := open(t)
	if err := s.Put(entry("p", "192.168.5.10", "tok", "o/r")); err != nil {
		t.Fatal(err)
	}
	deleted := make(chan struct{})
	s.afterRead = func() {
		go func() {
			defer close(deleted)
			if err := s.Delete("p"); err != nil {
				t.Error(err)
			}
		}()
		// Without the lock the Delete finishes inside this window and the
		// swap below would resurrect "p". With it, Delete waits for Reload.
		select {
		case <-deleted:
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	<-deleted
	if got := s.List(); len(got) != 0 {
		t.Fatalf("deleted project resurrected: %+v", got)
	}
	onDisk, err := Open(path)
	if err != nil || len(onDisk.List()) != 0 {
		t.Fatalf("file disagrees: %v %v", err, onDisk.List())
	}
}

func TestRegistryPersistsEgressOpen(t *testing.T) {
	s, path := open(t)
	e := entry("p", "192.168.5.10", "tok", "o/r")
	e.EgressOpen = true
	if err := s.Put(e); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(entry("q", "192.168.5.11", "tok2", "o/s")); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := s2.ByIP(netip.MustParseAddr("192.168.5.10")); !p.EgressOpen {
		t.Fatal("egress_open lost on reload")
	}
	if q, _ := s2.ByIP(netip.MustParseAddr("192.168.5.11")); q.EgressOpen {
		t.Fatal("egress_open set on a project that did not ask for it")
	}
}

func TestOpenReadsRegistryWithoutEgressOpen(t *testing.T) {
	// Registries written before egress_open existed load as closed.
	path := filepath.Join(t.TempDir(), "r.json")
	old := `[{"project":"p","vm_ip":"192.168.5.10","token_sha256":"` + strings.Repeat("ab", 32) +
		`","repos":["o/r"],"egress_extra":[]}]`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := s.ByIP(netip.MustParseAddr("192.168.5.10")); !ok || p.EgressOpen {
		t.Fatalf("ok=%v e=%+v", ok, p)
	}
}
