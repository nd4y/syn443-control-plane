//go:build postgres

package enrollment

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTelemetryAnalysisProcessRequiresVerifiedPostgresTLS(t *testing.T) {
	ca := os.Getenv("SYN443_TEST_DATABASE_CA")
	if ca == "" {
		t.Fatal("temporary PostgreSQL test CA required")
	}
	base, err := url.Parse(fixtureAnalysisDSN)
	if err != nil || base.Hostname() != "127.0.0.1" || base.Port() == "" {
		t.Fatal("temporary analysis database required")
	}
	for _, check := range []struct {
		name, host, trust string
		wantSuccess       bool
	}{
		{"trusted_name", "localhost", ca, true},
		{"wrong_name", "127.0.0.1", ca, false},
		{"unknown_ca", "localhost", "", false},
	} {
		t.Run(check.name, func(t *testing.T) {
			dsn := *base
			dsn.Host = net.JoinHostPort(check.host, base.Port())
			dsn.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {"system"}}.Encode()
			secret := filepath.Join(t.TempDir(), "analysis")
			if err := os.WriteFile(secret, []byte(dsn.String()), 0600); err != nil {
				t.Fatal("could not prepare test credential")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SYN443_TEST_BINARY_DIR"), "enrollment-admin"), "telemetry-aggregate-settled")
			cmd.Env = []string{"SYN443_TELEMETRY_ANALYSIS_DSN_FILE=" + secret}
			if check.trust != "" {
				cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+check.trust)
			}
			raw, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("TLS test exceeded its deadline")
			}
			if !check.wantSuccess {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || string(raw) != "enrollment_admin_failed\n" {
					t.Fatal("invalid server identity must produce only a fixed failure")
				}
				return
			}
			if err != nil || !strings.HasPrefix(string(raw), "Telemetry hour summarized: hour=") {
				t.Fatal("verified TLS session could not commit the aggregate")
			}
		})
	}
}
