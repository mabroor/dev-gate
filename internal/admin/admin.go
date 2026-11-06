// Package admin is the authenticated API through which the host tooling
// registers and revokes dev VMs.
package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/mabroor/dev-gate/internal/registry"
)

const maxBody = 64 << 10

type handler struct {
	reg       *registry.Store
	tokenHash [sha256.Size]byte
}

// New returns the admin handler. Every route requires
// "Authorization: Bearer <adminToken>".
func New(reg *registry.Store, adminToken string) (http.Handler, error) {
	if adminToken == "" {
		return nil, errors.New("admin: empty admin token")
	}
	h := &handler{reg: reg, tokenHash: sha256.Sum256([]byte(adminToken))}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /admin/projects/{project}", h.auth(h.put))
	mux.HandleFunc("PATCH /admin/projects/{project}", h.auth(h.patch))
	mux.HandleFunc("DELETE /admin/projects/{project}", h.auth(h.delete))
	mux.HandleFunc("GET /admin/projects", h.auth(h.list))
	return mux, nil
}

// auth compares SHA-256 digests in constant time, so neither the token's
// content nor its length is revealed by timing.
func (h *handler) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(tok))
		if !ok || subtle.ConstantTimeCompare(sum[:], h.tokenHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="dev-gate-admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type putRequest struct {
	VMIP        string   `json:"vm_ip"`
	TokenSHA256 string   `json:"token_sha256"`
	Repos       []string `json:"repos"`
	EgressExtra []string `json:"egress_extra"`
	EgressOpen  bool     `json:"egress_open"`
}

func (h *handler) put(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var in putRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	ip, err := netip.ParseAddr(in.VMIP)
	if err != nil || !ip.Unmap().Is4() {
		http.Error(w, "vm_ip must be an IPv4 address", http.StatusBadRequest)
		return
	}
	hash, err := hex.DecodeString(in.TokenSHA256)
	if err != nil || len(hash) != sha256.Size {
		http.Error(w, "token_sha256 must be 64 hex characters", http.StatusBadRequest)
		return
	}
	e := registry.Entry{Project: project, VMIP: ip.Unmap(), Repos: in.Repos, EgressExtra: in.EgressExtra, EgressOpen: in.EgressOpen}
	copy(e.TokenSHA256[:], hash)

	switch err := h.reg.Put(e); {
	case err == nil:
		slog.Info("admin: project registered", "project", project, "ip", e.VMIP, "repos", len(e.Repos), "egress_open", e.EgressOpen)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, registry.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, registry.ErrConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		slog.Error("admin: saving registry", "project", project, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type patchRequest struct {
	EgressExtra []string `json:"egress_extra"`
	EgressOpen  bool     `json:"egress_open"`
}

// patch changes only a registered project's egress, so CD can apply
// projects.yaml without the VM token that PUT needs.
func (h *handler) patch(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var in patchRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	switch err := h.reg.SetEgress(project, in.EgressExtra, in.EgressOpen); {
	case err == nil:
		slog.Info("admin: project egress set", "project", project, "egress_extra", len(in.EgressExtra), "egress_open", in.EgressOpen)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, registry.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, registry.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		slog.Error("admin: saving registry", "project", project, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	if err := h.reg.Delete(project); err != nil {
		slog.Error("admin: saving registry", "project", project, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	slog.Info("admin: project removed", "project", project)
	w.WriteHeader(http.StatusNoContent)
}

type listItem struct {
	Project     string   `json:"project"`
	VMIP        string   `json:"vm_ip"`
	Repos       []string `json:"repos"`
	EgressExtra []string `json:"egress_extra"`
	EgressOpen  bool     `json:"egress_open"`
}

func (h *handler) list(w http.ResponseWriter, _ *http.Request) {
	entries := h.reg.List()
	out := make([]listItem, 0, len(entries))
	for _, e := range entries {
		out = append(out, listItem{e.Project, e.VMIP.String(), orEmpty(e.Repos), orEmpty(e.EgressExtra), e.EgressOpen})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
