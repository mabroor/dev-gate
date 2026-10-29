package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `
listen: {git: ":8443", admin: ":9443", egress: ":3128"}
tls: {cert: /c.pem, key: /k.pem}
github_app: {id: "123", key_file: /app.pem}
admin_token_file: %s
registry_path: /var/lib/dev-gate/registry.json
egress_base_allow:
  - crates.io
  - "*.example.org"
`

func TestLoadValid(t *testing.T) {
	tok := write(t, "tok", strings.Repeat("a", 40)+"\n")
	c, err := Load(write(t, "c.yaml", strings.Replace(valid, "%s", tok, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.Admin != ":9443" || c.GitHubApp.ID != "123" || len(c.EgressBaseAllow) != 2 {
		t.Fatalf("%+v", c)
	}
	if got, err := c.AdminToken(); err != nil || got != strings.Repeat("a", 40) {
		t.Fatalf("token = %q, %v", got, err)
	}
}

func TestLoadRejectsBadConfigs(t *testing.T) {
	tok := write(t, "tok", strings.Repeat("a", 40))
	ok := strings.Replace(valid, "%s", tok, 1)
	cases := map[string]string{
		"unknown key":    ok + "\nsurprise: 1\n",
		"missing tls":    strings.Replace(ok, "tls: {cert: /c.pem, key: /k.pem}", "", 1),
		"missing app id": strings.Replace(ok, `id: "123"`, `id: ""`, 1),
		"no listen":      strings.Replace(ok, `listen: {git: ":8443", admin: ":9443", egress: ":3128"}`, "", 1),
		"not yaml":       "{{{",
	}
	for name, body := range cases {
		if _, err := Load(write(t, "c.yaml", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestAdminTokenTooShort(t *testing.T) {
	tok := write(t, "tok", "short\n")
	c, err := Load(write(t, "c.yaml", strings.Replace(valid, "%s", tok, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AdminToken(); err == nil {
		t.Fatal("short admin token accepted")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.EgressBaseAllow) < 19 {
		t.Fatalf("example base list has %d entries", len(c.EgressBaseAllow))
	}
}
