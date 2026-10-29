// Command dev-gate is the security boundary for sandboxed dev VMs: a git
// proxy that injects GitHub credentials, an admin API, and an allowlisting
// egress proxy.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mabroor/dev-gate/internal/admin"
	"github.com/mabroor/dev-gate/internal/config"
	"github.com/mabroor/dev-gate/internal/egress"
	"github.com/mabroor/dev-gate/internal/ghapp"
	"github.com/mabroor/dev-gate/internal/gitproxy"
	"github.com/mabroor/dev-gate/internal/registry"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

const shutdownTimeout = 30 * time.Second

func main() {
	var (
		configPath  = flag.String("config", "/etc/dev-gate/config.yaml", "path to the config file")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if *showVersion {
		fmt.Println(version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, *configPath); err != nil {
		slog.Error("dev-gate", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string) error {
	// Register before anything slow: until then SIGHUP's default action kills
	// the process, and a reload request can arrive while the listeners start.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	adminToken, err := cfg.AdminToken()
	if err != nil {
		return err
	}
	reg, err := registry.Open(cfg.RegistryPath)
	if err != nil {
		return err
	}
	pemBytes, err := os.ReadFile(cfg.GitHubApp.KeyFile)
	if err != nil {
		return err
	}
	key, err := ghapp.ParseKey(pemBytes)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	mint := &ghapp.Minter{AppID: cfg.GitHubApp.ID, Key: key, API: &url.URL{Scheme: "https", Host: "api.github.com"}}
	gitHandler := gitproxy.Handler(reg, mint, &url.URL{Scheme: "https", Host: "github.com"})
	adminHandler, err := admin.New(reg, adminToken)
	if err != nil {
		return err
	}
	var egressOpts []egress.Option
	if _, port, err := net.SplitHostPort(cfg.Listen.Egress); err == nil {
		if p, err := strconv.ParseUint(port, 10, 16); err == nil {
			egressOpts = append(egressOpts, egress.WithPort(uint16(p)))
		}
	}
	proxy, err := egress.New(reg, cfg.EgressBaseAllow, egressOpts...)
	if err != nil {
		return err
	}
	defer proxy.Close()

	servers := []*server{
		{"git", newHTTPServer(cfg.Listen.Git, gitHandler), true},
		{"admin", newHTTPServer(cfg.Listen.Admin, adminHandler), true},
		{"egress", newHTTPServer(cfg.Listen.Egress, proxy.Handler()), false},
	}
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		ln, err := net.Listen("tcp", s.srv.Addr)
		if err != nil {
			return fmt.Errorf("%s listener: %w", s.name, err)
		}
		slog.Info("listening", "server", s.name, "addr", ln.Addr().String(), "version", version)
		if s.tls {
			ln = tls.NewListener(ln, tlsCfg)
		}
		go func() {
			if err := s.srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s server: %w", s.name, err)
			}
		}()
	}

	for {
		select {
		case <-hup:
			if err := reg.Reload(); err != nil {
				slog.Error("registry reload failed; keeping current state", "err", err)
			} else {
				slog.Info("registry reloaded", "projects", len(reg.List()))
			}
		case err := <-errCh:
			shutdown(servers)
			return err
		case <-ctx.Done():
			slog.Info("shutting down")
			shutdown(servers)
			return nil
		}
	}
}

type server struct {
	name string
	srv  *http.Server
	tls  bool
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
}

func shutdown(servers []*server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, s := range servers {
		if err := s.srv.Shutdown(ctx); err != nil {
			slog.Warn("shutdown", "server", s.name, "err", err)
		}
	}
}
