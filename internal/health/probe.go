package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// LoopbackProbe identifies a local listener independently of the public gateway.
type LoopbackProbe struct {
	Listen, Origin, Certificate, ServerName string
	FixtureHTTP                             bool
}

// ProbeLocalService dials only the process's configured loopback socket, even when its TLS name
// belongs to the public gateway. The probe needs no SQL credential or TLS key.
func ProbeLocalService(ctx context.Context, c LoopbackProbe, service string) error {
	invalid := errors.New("local readiness unavailable")
	if service == "" {
		return invalid
	}
	ip, port, err := net.SplitHostPort(c.Listen)
	if err != nil || !net.ParseIP(ip).IsLoopback() {
		return invalid
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return invalid
	}
	origin, err := url.Parse(c.Origin)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" {
		return invalid
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", c.Listen)
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	switch origin.Scheme {
	case "https":
		f, err := os.Open(c.Certificate)
		if err != nil {
			return invalid
		}
		defer f.Close()
		pem, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
		roots := x509.NewCertPool()
		if err != nil || len(pem) > 64<<10 || !roots.AppendCertsFromPEM(pem) {
			return invalid
		}
		name := c.ServerName
		if name == "" {
			name = origin.Hostname()
		}
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name}
	case "http":
		if !c.FixtureHTTP || origin.Hostname() != "127.0.0.1" || origin.Port() == "" {
			return invalid
		}
	default:
		return invalid
	}
	probe, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probe, http.MethodHead, c.Origin+"/readyz", nil)
	if err != nil {
		return invalid
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return invalid
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("X-SYN443-Service") != service {
		return invalid
	}
	return nil
}
