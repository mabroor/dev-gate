package pktline

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

const (
	zero = "0000000000000000000000000000000000000000"
	sha1 = "1111111111111111111111111111111111111111"
)

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func cmd(ref string) string { return zero + " " + sha1 + " " + ref }

func TestReceivePackParsesRefs(t *testing.T) {
	body := pkt(cmd("refs/heads/agent/x")+"\x00report-status side-band-64k") + "0000" + "PACKdata"
	refs, _, err := CommandRefs(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	want := RefUpdate{Old: zero, New: sha1, Ref: "refs/heads/agent/x"}
	if len(refs) != 1 || refs[0] != want {
		t.Fatalf("got %+v, want [%+v]", refs, want)
	}
	if !AllAgent(refs) {
		t.Fatal("AllAgent = false for agent ref")
	}
}

func TestReceivePackParsesMultipleCommands(t *testing.T) {
	body := pkt(cmd("refs/heads/agent/a")+"\x00caps") + pkt(cmd("refs/heads/agent/b")) + "0000"
	refs, _, err := CommandRefs(strings.NewReader(body))
	if err != nil || len(refs) != 2 {
		t.Fatalf("refs=%+v err=%v", refs, err)
	}
}

func TestReceivePackRejectsMixedRefs(t *testing.T) {
	body := pkt(cmd("refs/heads/agent/x")+"\x00caps") + pkt(cmd("refs/heads/main")) + "0000"
	refs, _, err := CommandRefs(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("got %d refs", len(refs))
	}
	if AllAgent(refs) {
		t.Fatal("AllAgent = true for mixed refs")
	}
}

func TestReceivePackRejectsAgentLookalikes(t *testing.T) {
	for _, ref := range []string{
		"refs/heads/agent",
		"refs/heads/agent/",
		"refs/heads/agentx/y",
		"refs/tags/agent/x",
		"refs/heads/agent/../main",
		"refs/heads/agent//x",
		"refs/heads/Agent/x",
		"agent/x",
	} {
		if AllAgent([]RefUpdate{{Ref: ref}}) {
			t.Errorf("AllAgent(%q) = true", ref)
		}
	}
	if AllAgent(nil) {
		t.Error("AllAgent(nil) = true")
	}
}

func TestReceivePackRejectsMalformed(t *testing.T) {
	for name, body := range map[string]string{
		"push-cert":     pkt("push-cert\x00caps") + pkt("certificate version 0.1") + "0000",
		"short-hash":    pkt("abc def refs/heads/agent/x") + "0000",
		"missing-flush": pkt(cmd("refs/heads/agent/x") + "\x00caps"),
		"bad-length":    "zzzz",
		"delim":         "0001",
		"len-too-small": "0003",
		"empty":         "",
		"flush-only":    "0000",
		"nul-late":      pkt(cmd("refs/heads/agent/x")+"\x00caps") + pkt(cmd("refs/heads/main")+"\x00caps") + "0000",
		"space-in-ref":  pkt(zero+" "+sha1+" refs/heads/agent/x y") + "0000",
	} {
		if _, _, err := CommandRefs(strings.NewReader(body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestCommandSectionIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(pkt(cmd("refs/heads/agent/x") + "\x00caps"))
	for range 100000 {
		b.WriteString(pkt(cmd("refs/heads/agent/x")))
	}
	b.WriteString("0000")
	if _, _, err := CommandRefs(strings.NewReader(b.String())); err == nil {
		t.Fatal("expected error for oversized command section")
	}
}

func TestReplayReaderReturnsWholeBody(t *testing.T) {
	body := pkt(cmd("refs/heads/agent/x")+"\x00caps") + "0000" + strings.Repeat("PACK", 10000)
	_, r, err := CommandRefs(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(body)) {
		t.Fatalf("replay differs: got %d bytes, want %d", len(got), len(body))
	}
}
