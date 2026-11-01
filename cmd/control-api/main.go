// The control API verifies a distinct administrative audience and live SQL ACL.
// It never receives a signing key or migrations/ACL-owner database privileges.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func run() error {
	raw, e := enrollment.PrivateFile(os.Getenv("SYN443_CONTROL_CONFIG"), 65536)
	if e != nil {
		return e
	}
	c, e := catalog.ParseRuntimeConfig(raw)
	if e != nil || c.ValidateAdmin() != nil {
		return catalog.ErrInvalid
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return catalog.ErrInvalid
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, e := catalog.OpenStore(c)
	if e != nil {
		return e
	}
	defer store.DB.Close()
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	e = store.RuntimeRole(check, false)
	cancel()
	if e != nil {
		return e
	}
	var providers catalog.VerifierGroup
	for _, client := range c.ClientIDs {
		provider, err := identity.NewProvider(ctx, c.Issuer, c.Audience, client, nil, c.FixtureHTTP)
		if err != nil {
			return err
		}
		providers = append(providers, provider)
	}
	api, e := catalog.NewAPI(store, providers, c.Origin, c.AssuranceACR, c.FixtureHTTP)
	if e != nil {
		return e
	}
	server := &http.Server{Addr: c.Listen, Handler: api, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32768, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		server.Shutdown(shut)
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
	if run() != nil {
		fmt.Fprintln(os.Stderr, "control_api_failed")
		os.Exit(1)
	}
}
