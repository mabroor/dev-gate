// Command dev-gate serves the git proxy for sandboxed dev VMs.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/mabroor/dev-gate/internal/ghapp"
	"github.com/mabroor/dev-gate/internal/gitproxy"
	"github.com/mabroor/dev-gate/internal/registry"
)

func main() {
	var (
		registryPath = flag.String("registry", "registry.json", "path to the VM registry file")
		listen       = flag.String("listen", ":8443", "git proxy listen address")
		certFile     = flag.String("tls-cert", "", "TLS certificate file")
		keyFile      = flag.String("tls-key", "", "TLS private key file")
		appID        = flag.String("app-id", "", "GitHub App id")
		appKeyPath   = flag.String("app-key", "", "path to the GitHub App private key (PEM)")
	)
	flag.Parse()

	if err := run(*registryPath, *listen, *certFile, *keyFile, *appID, *appKeyPath); err != nil {
		slog.Error("dev-gate", "err", err)
		os.Exit(1)
	}
}

func run(registryPath, listen, certFile, keyFile, appID, appKeyPath string) error {
	if certFile == "" || keyFile == "" || appID == "" || appKeyPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	reg, err := registry.Open(registryPath)
	if err != nil {
		return err
	}
	pemBytes, err := os.ReadFile(appKeyPath)
	if err != nil {
		return err
	}
	key, err := ghapp.ParseKey(pemBytes)
	if err != nil {
		return err
	}
	mint := &ghapp.Minter{AppID: appID, Key: key, API: &url.URL{Scheme: "https", Host: "api.github.com"}}
	upstream := &url.URL{Scheme: "https", Host: "github.com"}

	srv := &http.Server{
		Addr:              listen,
		Handler:           gitproxy.Handler(reg, mint, upstream),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	slog.Info("git proxy listening", "addr", listen)
	return srv.ListenAndServeTLS(certFile, keyFile)
}
