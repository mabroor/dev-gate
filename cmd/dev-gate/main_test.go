package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeConfig creates a runnable config in a temp dir and returns its path
// and the admin address.
func writeConfig(t *testing.T) (cfgPath, adminAddr string) {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "cert.pem"), "CERTIFICATE", der)
	writePEM(t, filepath.Join(dir, "key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	writePEM(t, filepath.Join(dir, "app.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	if err := os.WriteFile(filepath.Join(dir, "tok"), []byte(strings.Repeat("a", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	adminAddr = freeAddr(t)
	cfg := fmt.Sprintf(`
listen: {git: %q, admin: %q, egress: %q}
tls: {cert: %s/cert.pem, key: %s/key.pem}
github_app: {id: "1", key_file: %s/app.pem}
admin_token_file: %s/tok
registry_path: %s/registry.json
egress_base_allow: [example.com]
`, freeAddr(t), adminAddr, freeAddr(t), dir, dir, dir, dir, dir)
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, adminAddr
}

func TestRunServesReloadsOnSIGHUPAndShutsDown(t *testing.T) {
	cfgPath, adminAddr := writeConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("https://" + adminAddr + "/admin/projects")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("admin without bearer: %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("admin never came up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The process must survive SIGHUP (reload), not die from its default action.
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("run exited after SIGHUP: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}
}
