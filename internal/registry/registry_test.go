package registry

import (
	"crypto/sha256"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
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
