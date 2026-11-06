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
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/mabroor/dev-gate/internal/ghapp"
)

// ErrInvalid marks an entry that is malformed; ErrConflict one that collides
// with another project's IP or token; ErrNotFound an unknown project.
var (
	ErrNotFound = errors.New("registry: no such project")
	ErrInvalid  = errors.New("registry: invalid entry")
	ErrConflict = errors.New("registry: conflicts with another project")
)

var (
	projectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	hostRE    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// ValidProject reports whether name is an acceptable project name.
func ValidProject(name string) bool { return projectRE.MatchString(name) }

// validEgressHost accepts a lowercase hostname of at least two labels, with an
// optional leading "*." wildcard.
func validEgressHost(h string) bool {
	return len(h) <= 253 && hostRE.MatchString(strings.TrimPrefix(h, "*."))
}

func validate(e Entry) error {
	switch {
	case !ValidProject(e.Project):
		return fmt.Errorf("%w: bad project name", ErrInvalid)
	case !e.VMIP.IsValid():
		return fmt.Errorf("%w: bad vm ip", ErrInvalid)
	case e.TokenSHA256 == [32]byte{}:
		return fmt.Errorf("%w: no token hash", ErrInvalid)
	case len(e.Repos) == 0:
		return fmt.Errorf("%w: no repos", ErrInvalid)
	}
	for _, r := range e.Repos {
		if !ghapp.ValidRepo(r) {
			return fmt.Errorf("%w: bad repo %q", ErrInvalid, r)
		}
	}
	for _, h := range e.EgressExtra {
		if !validEgressHost(h) {
			return fmt.Errorf("%w: bad egress host %q", ErrInvalid, h)
		}
	}
	return nil
}

// checkConflict reports a collision between e and any other project in m.
func checkConflict(m map[string]Entry, e Entry) error {
	for p, o := range m {
		if p == e.Project {
			continue
		}
		if o.VMIP == e.VMIP {
			return fmt.Errorf("%w: ip %s belongs to project %q", ErrConflict, e.VMIP, p)
		}
		if o.TokenSHA256 == e.TokenSHA256 {
			return fmt.Errorf("%w: token already used by project %q", ErrConflict, p)
		}
	}
	return nil
}

// Entry is one project's dev VM.
type Entry struct {
	Project     string
	VMIP        netip.Addr
	TokenSHA256 [32]byte
	Repos       []string // "owner/repo"
	EgressExtra []string
	// EgressOpen lets the project's VM reach any public host, not just the
	// allowlist. Private, loopback and link-local addresses stay refused.
	EgressOpen bool
	// CILogs lets the VM read failed-job log tails through GET /ci. Off by
	// default: turn it on only when the project's CI gives agent runs no
	// secrets.
	CILogs bool
}

// wire is the on-disk form; the token hash is hex rather than a number array.
type wire struct {
	Project     string     `json:"project"`
	VMIP        netip.Addr `json:"vm_ip"`
	TokenSHA256 string     `json:"token_sha256"`
	Repos       []string   `json:"repos"`
	EgressExtra []string   `json:"egress_extra"`
	EgressOpen  bool       `json:"egress_open,omitempty"`
	CILogs      bool       `json:"ci_logs,omitempty"`
}

func (e Entry) MarshalJSON() ([]byte, error) {
	return json.Marshal(wire{e.Project, e.VMIP, hex.EncodeToString(e.TokenSHA256[:]), e.Repos, e.EgressExtra, e.EgressOpen, e.CILogs})
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
	*e = Entry{Project: w.Project, VMIP: w.VMIP, Repos: w.Repos, EgressExtra: w.EgressExtra, EgressOpen: w.EgressOpen, CILogs: w.CILogs}
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

	// afterRead, if set, runs in Reload between reading the file and swapping
	// the map. Tests use it to interleave a concurrent change.
	afterRead func()
}

// Open loads the registry at path. A missing file is an empty registry; a
// corrupt or inconsistent one is an error.
func Open(path string) (*Store, error) {
	m, err := load(path)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, byP: m}, nil
}

// Reload re-reads the registry file. On any error the current state is kept.
// The lock is held across the read and the swap, so a Put or Delete that saves
// concurrently cannot be overwritten by an older snapshot of the file.
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := load(s.path)
	if err != nil {
		return err
	}
	if s.afterRead != nil {
		s.afterRead()
	}
	s.byP = m
	return nil
}

func load(path string) (map[string]Entry, error) {
	m := map[string]Entry{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	var entries []Entry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("registry: parsing %s: %w", path, err)
	}
	for _, e := range entries {
		if err := validate(e); err != nil {
			return nil, fmt.Errorf("registry: %s: project %q: %w", path, e.Project, err)
		}
		e.VMIP = e.VMIP.Unmap()
		if _, dup := m[e.Project]; dup {
			return nil, fmt.Errorf("registry: %s: duplicate project %q", path, e.Project)
		}
		if err := checkConflict(m, e); err != nil {
			return nil, fmt.Errorf("registry: %s: project %q: %w", path, e.Project, err)
		}
		m[e.Project] = e.clone()
	}
	return m, nil
}

// Put adds or replaces the entry for e.Project.
func (s *Store) Put(e Entry) error {
	if err := validate(e); err != nil {
		return err
	}
	e = e.clone()
	e.VMIP = e.VMIP.Unmap()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := checkConflict(s.byP, e); err != nil {
		return err
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

// Policy is the part of an entry that CD may change without the VM token.
type Policy struct {
	EgressExtra []string
	EgressOpen  bool
	CILogs      bool
}

// SetPolicy replaces a registered project's policy and keeps its VM address,
// token and repos, so the policy can change without the VM's token.
func (s *Store) SetPolicy(project string, p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.byP[project]
	if !ok {
		return ErrNotFound
	}
	e := prev.clone()
	e.EgressExtra = append([]string(nil), p.EgressExtra...)
	e.EgressOpen = p.EgressOpen
	e.CILogs = p.CILogs
	if err := validate(e); err != nil {
		return err
	}
	s.byP[project] = e
	if err := s.saveLocked(); err != nil {
		s.byP[project] = prev
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

// List returns copies of all entries, sorted by project.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sortedLocked()
}

func (s *Store) sortedLocked() []Entry {
	entries := make([]Entry, 0, len(s.byP))
	for _, e := range s.byP {
		entries = append(entries, e.clone())
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Project, b.Project) })
	return entries
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
	entries := s.sortedLocked()
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
