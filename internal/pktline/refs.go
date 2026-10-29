// Package pktline parses the command section of a git receive-pack request.
package pktline

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	agentPrefix = "refs/heads/agent/"

	// maxPktLen is the largest pkt-line git allows, including the length prefix.
	maxPktLen = 65520
	// maxCommandBytes bounds how much of the body is buffered before the flush
	// packet; the pack that follows is never buffered.
	maxCommandBytes = 1 << 20
)

// RefUpdate is one command from a receive-pack request.
type RefUpdate struct {
	Old, New, Ref string
}

// CommandRefs reads the command list at the start of a receive-pack body, up
// to and including the first flush packet. The returned reader replays the
// whole body: the bytes consumed here followed by the unread remainder.
//
// It is strict on purpose: anything that is not a plain "<old> <new> <ref>"
// command (push certificates, shallow lines, malformed hashes) is an error, so
// the caller can never authorise a request whose real commands it did not see.
func CommandRefs(body io.Reader) ([]RefUpdate, io.Reader, error) {
	var seen bytes.Buffer
	var refs []RefUpdate

	for first := true; ; first = false {
		line, flush, err := readPkt(body, &seen)
		if err != nil {
			return nil, nil, err
		}
		if flush {
			break
		}
		upd, err := parseCommand(line, first)
		if err != nil {
			return nil, nil, err
		}
		refs = append(refs, upd)
	}
	if len(refs) == 0 {
		return nil, nil, errors.New("pktline: no commands before flush")
	}
	return refs, io.MultiReader(&seen, body), nil
}

// AllAgent reports whether every ref is refs/heads/agent/<something>. An empty
// list is false.
func AllAgent(refs []RefUpdate) bool {
	if len(refs) == 0 {
		return false
	}
	for _, r := range refs {
		rest, ok := strings.CutPrefix(r.Ref, agentPrefix)
		if !ok || rest == "" || strings.Contains(rest, "..") ||
			strings.Contains(r.Ref, "//") || strings.HasSuffix(rest, "/") {
			return false
		}
	}
	return true
}

// readPkt reads one pkt-line, appending every byte read to seen. It returns
// flush=true for "0000".
func readPkt(r io.Reader, seen *bytes.Buffer) (payload string, flush bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", false, fmt.Errorf("pktline: reading length: %w", err)
	}
	seen.Write(hdr[:])
	n, err := strconv.ParseUint(string(hdr[:]), 16, 32)
	if err != nil {
		return "", false, fmt.Errorf("pktline: bad length %q", hdr[:])
	}
	switch {
	case n == 0:
		return "", true, nil
	case n < 4 || n > maxPktLen:
		return "", false, fmt.Errorf("pktline: unsupported length %d", n)
	}
	if seen.Len()+int(n)-4 > maxCommandBytes {
		return "", false, errors.New("pktline: command section too large")
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", false, fmt.Errorf("pktline: reading payload: %w", err)
	}
	seen.Write(buf)
	return string(buf), false, nil
}

func parseCommand(line string, first bool) (RefUpdate, error) {
	line = strings.TrimSuffix(line, "\n")
	cmd, _, hasNUL := strings.Cut(line, "\x00")
	if hasNUL && !first {
		return RefUpdate{}, errors.New("pktline: capabilities after first command")
	}
	parts := strings.Split(cmd, " ")
	if len(parts) != 3 || !isHash(parts[0]) || !isHash(parts[1]) || !validRef(parts[2]) {
		return RefUpdate{}, errors.New("pktline: malformed command")
	}
	return RefUpdate{Old: parts[0], New: parts[1], Ref: parts[2]}, nil
}

func isHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func validRef(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}
