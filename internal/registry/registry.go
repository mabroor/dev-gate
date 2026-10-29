// Package registry stores the dev VMs dev-gate serves: which project each VM
// belongs to, which repos it may reach, and the hash of its bearer token.
package registry

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// Entry is one project's dev VM.
type Entry struct {
	Project     string
	VMIP        netip.Addr
	TokenSHA256 [32]byte
	Repos       []string // "owner/repo"
	EgressExtra []string
}

// wire is the on-disk form; the token hash is hex rather than a number array.
type wire struct {
	Project     string     `json:"project"`
	VMIP        netip.Addr `json:"vm_ip"`
	TokenSHA256 string     `json:"token_sha256"`
	Repos       []string   `json:"repos"`
	EgressExtra []string   `json:"egress_extra"`
}

func (e Entry) MarshalJSON() ([]byte, error) {
	return json.Marshal(wire{e.Project, e.VMIP, hex.EncodeToString(e.TokenSHA256[:]), e.Repos, e.EgressExtra})
}

func (e *Entry) UnmarshalJSON(b []byte) error {
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	h, err := hex.DecodeString(w.TokenSHA256)
	if err != nil || len(h) != sha256.Size {
		return errors.New("registry: bad token_sha256")
	}
	*e = Entry{Project: w.Project, VMIP: w.VMIP, Repos: w.Repos, EgressExtra: w.EgressExtra}
	copy(e.TokenSHA256[:], h)
	return nil
}

func (e Entry) clone() Entry {
	e.Repos = slices.Clone(e.Repos)
	e.EgressExtra = slices.Clone(e.EgressExtra)
	return e
}

// Store is a concurrency-safe registry persisted to a JSON file.
type Store struct {
	path string
	mu   sync.RWMutex
	byP  map[string]Entry
}

// Open loads the registry at path. A missing file is an empty registry; a
// corrupt one is an error.
func Open(path string) (*Store, error) {
	s := &Store{path: path, byP: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	var entries []Entry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("registry: parsing %s: %w", path, err)
	}
	for _, e := range entries {
		s.byP[e.Project] = e
	}
	return s, nil
}

// Put adds or replaces the entry for e.Project.
func (s *Store) Put(e Entry) error {
	if e.Project == "" || !e.VMIP.IsValid() || len(e.Repos) == 0 {
		return errors.New("registry: entry needs project, vm ip and repos")
	}
	e = e.clone()
	e.VMIP = e.VMIP.Unmap()

	s.mu.Lock()
	defer s.mu.Unlock()
	for p, o := range s.byP {
		if p != e.Project && o.VMIP == e.VMIP {
			return fmt.Errorf("registry: ip %s already belongs to project %q", e.VMIP, p)
		}
	}
	prev, had := s.byP[e.Project]
	s.byP[e.Project] = e
	if err := s.saveLocked(); err != nil {
		if had {
			s.byP[e.Project] = prev
		} else {
			delete(s.byP, e.Project)
		}
		return err
	}
	return nil
}

// Delete removes a project; deleting an unknown project is not an error.
func (s *Store) Delete(project string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.byP[project]
	if !had {
		return nil
	}
	delete(s.byP, project)
	if err := s.saveLocked(); err != nil {
		s.byP[project] = prev
		return err
	}
	return nil
}

// ByToken returns the entry whose token matches and whose VM has address ip.
// A valid token presented from any other address finds nothing.
func (s *Store) ByToken(token string, ip netip.Addr) (Entry, bool) {
	e, ok := s.byToken(token)
	if !ok || e.VMIP != ip.Unmap() {
		return Entry{}, false
	}
	return e.clone(), true
}

// HasToken reports whether token belongs to any entry, regardless of source
// address. It lets callers tell a stolen token (wrong IP) from a bad one.
func (s *Store) HasToken(token string) bool {
	_, ok := s.byToken(token)
	return ok
}

// byToken compares against every entry in constant time per comparison and
// does not stop early, so timing does not reveal which entry matched.
func (s *Store) byToken(token string) (Entry, bool) {
	if token == "" {
		return Entry{}, false
	}
	sum := sha256.Sum256([]byte(token))
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found Entry
	ok := false
	for _, e := range s.byP {
		if subtle.ConstantTimeCompare(sum[:], e.TokenSHA256[:]) == 1 {
			found, ok = e, true
		}
	}
	return found, ok
}

// ByIP returns the entry for the VM at ip.
func (s *Store) ByIP(ip netip.Addr) (Entry, bool) {
	ip = ip.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.byP {
		if e.VMIP == ip {
			return e.clone(), true
		}
	}
	return Entry{}, false
}

// saveLocked writes the registry to a 0600 temp file and renames it into place.
func (s *Store) saveLocked() error {
	entries := make([]Entry, 0, len(s.byP))
	for _, e := range s.byP {
		entries = append(entries, e)
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		switch {
		case a.Project < b.Project:
			return -1
		case a.Project > b.Project:
			return 1
		}
		return 0
	})
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".registry-*")
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("registry: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("registry: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("registry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	// Without the directory fsync a power loss can undo the rename, and with
	// it a DELETE.
	if err := syncDir(filepath.Dir(s.path)); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}
