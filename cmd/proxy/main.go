package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/example/socks5-proxy-go/socks5"
)

func main() {
	addr := envOr("PROXY_ADDR", "0.0.0.0:1080")
	user := os.Getenv("PROXY_USER")
	pass := os.Getenv("PROXY_PASS")
	allowedHosts := os.Getenv("PROXY_ALLOW_HOSTS") // comma-separated, empty = allow all
	dialTimeout := 10 * time.Second

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[socks5-proxy-go] ")

	cfg := socks5.Config{
		DialTimeout: dialTimeout,
	}

	// ── Optional username/password auth ───────────────────────────────────
	if user != "" && pass != "" {
		cfg.Credentials = socks5.Credentials{user: pass}
		log.Printf("auth: user/password enabled (user=%q)", user)
	} else {
		log.Printf("auth: none (no PROXY_USER/PROXY_PASS set)")
	}

	// ── Optional destination allow-list ───────────────────────────────────
	if allowedHosts != "" {
		allowed := make(map[string]struct{})
		for _, h := range strings.Split(allowedHosts, ",") {
			allowed[strings.TrimSpace(strings.ToLower(h))] = struct{}{}
		}
		cfg.Rules = func(_ context.Context, a socks5.AddrSpec) bool {
			host := strings.ToLower(a.FQDN)
			if host == "" {
				host = a.IP.String()
			}
			_, ok := allowed[host]
			return ok
		}
		log.Printf("rules: allow-list active (%d entries)", len(allowed))
	}

	srv := socks5.New(cfg)

	// ── Listener ──────────────────────────────────────────────────────────
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("listening on %s", ln.Addr())

	// ── Graceful shutdown on SIGINT / SIGTERM ─────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %s, shutting down…", sig)
		ln.Close()
	}()

	if err := srv.Serve(ln); err != nil {
		log.Printf("server stopped: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
