// Receives device telemetry behind the public origin's exact path route.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/health"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type config struct {
	Listen         string `json:"listen"`
	Origin         string `json:"origin"`
	DatabaseFile   string `json:"databaseFile"`
	Certificate    string `json:"certificate"`
	CertificateKey string `json:"certificateKey"`
	FixtureHTTP    bool   `json:"fixtureHttp"`
}

func run(ctx context.Context) error {
	raw, err := enrollment.PrivateFile(os.Getenv("SYN443_TELEMETRY_CONFIG"), 16384)
	if err != nil {
		return err
	}
	var c config
	if identity.Decode(raw, &c, true) != nil {
		return identity.ErrInvalid
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return identity.ErrInvalid
	}
	dsn, err := enrollment.PrivateFile(c.DatabaseFile, 8192)
	if err != nil {
		return err
	}
	defer clear(dsn)
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	service, err := enrollment.OpenStandaloneIngest(check, strings.TrimSpace(string(dsn)), c.Origin, c.FixtureHTTP)
	cancel()
	if err != nil {
		return err
	}
	defer service.Close()
	server := &http.Server{
		Addr: c.Listen, Handler: health.Wrap(ctx, service, service.Ready),
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	plain := c.FixtureHTTP && strings.HasPrefix(c.Origin, "http://")
	if !plain {
		key, err := enrollment.PrivateFile(c.CertificateKey, 16384)
		if err != nil {
			return err
		}
		defer clear(key)
		certPEM, err := os.ReadFile(c.Certificate)
		if err != nil {
			return err
		}
		pair, err := tls.X509KeyPair(certPEM, key)
		if err != nil {
			return err
		}
		server.TLSConfig.Certificates = []tls.Certificate{pair}
	}
	if plain {
		err = server.ListenAndServe()
	} else {
		err = server.ListenAndServeTLS("", "")
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) != 1 || run(ctx) != nil {
		fmt.Fprintln(os.Stderr, "telemetry_ingest_unavailable")
		os.Exit(1)
	}
}
