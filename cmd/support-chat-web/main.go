package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/nd4y/syn443-control-plane/internal/chatweb"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/health"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func run(ctx context.Context, check bool) error {
	raw, e := enrollment.PrivateFile(os.Getenv("SYN443_CHAT_WEB_CONFIG"), 16384)
	if e != nil {
		return e
	}
	defer clear(raw)
	var c chatweb.Config
	if identity.Decode(raw, &c, true) != nil {
		return identity.ErrInvalid
	}
	if c.ControlConsole && !chatweb.ControlAssetsReady() {
		return errors.New("control console bundle is missing")
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return identity.ErrInvalid
	}
	if check {
		return health.ProbeLocalService(ctx, health.LoopbackProbe{
			Listen: c.Listen, Origin: c.Origin, Certificate: c.Certificate, ServerName: c.ReadinessServerName, FixtureHTTP: c.FixtureHTTP,
		}, "support-chat-web")
	}
	handler, e := chatweb.New(ctx, c, nil)
	if e != nil {
		return e
	}
	defer handler.Close()
	ready := health.Wrap(ctx, handler, func(check context.Context) error { return check.Err() })
	withIdentity := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.Header().Set("X-SYN443-Service", "support-chat-web")
		}
		ready.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: c.Listen, Handler: withIdentity, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(stop)
	}()
	if c.FixtureHTTP && strings.HasPrefix(c.Origin, "http://") {
		e = server.ListenAndServe()
	} else {
		if _, e = enrollment.PrivateFile(c.CertificateKey, 8192); e != nil {
			return e
		}
		e = server.ListenAndServeTLS(c.Certificate, c.CertificateKey)
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func main() {
	check := len(os.Args) == 2 && os.Args[1] == "--check-ready"
	if len(os.Args) != 1 && !check {
		fmt.Fprintln(os.Stderr, "usage: support-chat-web [--check-ready]")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if run(ctx, check) != nil {
		fmt.Fprintln(os.Stderr, "chat_web_failed")
		os.Exit(1)
	}
}
