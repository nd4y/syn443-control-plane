package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/nd4y/syn443-control-plane/internal/chatweb"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run() error {
	raw, e := enrollment.PrivateFile(os.Getenv("SYN443_CHAT_WEB_CONFIG"), 16384)
	if e != nil {
		return e
	}
	var c chatweb.Config
	if identity.Decode(raw, &c, true) != nil {
		return identity.ErrInvalid
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return identity.ErrInvalid
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	handler, e := chatweb.New(ctx, c, nil)
	if e != nil {
		return e
	}
	defer handler.Close()
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(stop)
	}()
	if c.FixtureHTTP {
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
	if run() != nil {
		fmt.Fprintln(os.Stderr, "chat_web_failed")
		os.Exit(1)
	}
}
