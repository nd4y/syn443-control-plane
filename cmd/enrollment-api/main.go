// The enrollment pilot is separately configured and loopback-bound. No signing key is loaded.
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

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

func run() error {
	c, e := enrollment.ReadConfig(os.Getenv("SYN443_ENROLLMENT_CONFIG"))
	if e != nil {
		return e
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return identity.ErrInvalid
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, e := enrollment.OpenStore(c)
	if e != nil {
		return e
	}
	defer store.DB.Close()
	store.OverlayBrokerPending = c.OverlayBrokerEnabled
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	e = store.RuntimeRole(check, false)
	cancel()
	if e != nil {
		return e
	}
	provider, e := identity.NewProvider(ctx, c.Issuer, c.Audience, c.ClientID, nil, c.FixtureHTTP)
	if e != nil {
		return e
	}
	roots, e := enrollment.PublicRoots(c)
	if e != nil {
		return e
	}
	api, e := enrollment.NewAPI(store, provider, c.Origin, roots, c.FixtureHTTP)
	if e != nil {
		return e
	}
	if path := os.Getenv("SYN443_INVITATION_CONFIG"); path != "" {
		ic, err := invitation.ReadConfig(path, time.Now())
		if err != nil || ic.IdentityOrigin != c.Origin || ic.Issuer != c.Issuer {
			return identity.ErrInvalid
		}
		is, err := invitation.NewStore(store.DB, ic.Key())
		if err != nil {
			return err
		}
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = is.RuntimeRole(check, "syn443_identity_api")
		cancel()
		if err != nil {
			return err
		}
		d, _, err := bootstrap.VerifyDescriptor(ic.Descriptor, ic.Anchor, bootstrap.Floor{}, time.Now())
		if err != nil {
			return err
		}
		if c.OverlayServiceID != "" && c.OverlayServiceID != d.ServiceID {
			return identity.ErrInvalid
		}
		store.Reservations = is.Reservations
		api.Invitations = &invitation.DeviceService{Store: is, Identity: store, Origin: c.Origin, ServiceID: d.ServiceID}
	}
	api.OverlayServiceID = c.OverlayServiceID
	if c.ControlPanelDiscovery {
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = store.ControlPanelRole(check)
		cancel()
		if e != nil {
			return e
		}
	}
	api.ControlPanelDiscovery = c.ControlPanelDiscovery
	api.ChatEnabled = c.ChatEnabled
	api.ChatWebOrigin = c.ChatWebOrigin
	if c.ChatWebOrigin != "" {
		api.ChatVerifier, e = identity.NewProvider(ctx, c.Issuer, c.ChatWebAudience, c.ChatWebClientID, nil, c.FixtureHTTP)
		if e != nil {
			return e
		}
	}
	server := &http.Server{Addr: c.Listen, Handler: api, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shut)
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
		fmt.Fprintln(os.Stderr, "enrollment_api_failed")
		os.Exit(1)
	}
}
