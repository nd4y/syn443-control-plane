package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

var errTelemetryPruneWorker = errors.New("telemetry_prune_worker_unavailable")
var errTelemetryAggregateSettled = errors.New("telemetry_aggregate_settled_unavailable")

type scopedTelemetryDSN struct {
	fileVariable string
	role         string
	unavailable  error
}

var retentionTelemetryDSN = scopedTelemetryDSN{
	fileVariable: "SYN443_TELEMETRY_RETENTION_DSN_FILE",
	role:         "syn443_telemetry_retention",
	unavailable:  errTelemetryPruneWorker,
}

var analysisTelemetryDSN = scopedTelemetryDSN{
	fileVariable: "SYN443_TELEMETRY_ANALYSIS_DSN_FILE",
	role:         "syn443_telemetry_analysis",
	unavailable:  errTelemetryAggregateSettled,
}

const telemetryWorkerInterval = time.Minute

// A new, deliberately narrower DSN boundary. The one-shot operator commands
// retain their existing parser. Ambient libpq settings cannot select another
// endpoint, credentials, service file or certificate for this process.
var telemetryAmbientVariables = [...]string{
	"PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD",
	"PGPASSFILE", "PGSERVICE", "PGSERVICEFILE", "PGSYSCONFDIR", "PGSSLMODE",
	"PGREQUIRESSL", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGSSLCRL",
	"PGSSLCRLDIR", "PGSSLNEGOTIATION", "PGSSLSNI", "PGSSLCOMPRESSION", "PGSSLPASSWORD",
	"PGSSL_MIN_PROTOCOL_VERSION", "PGSSL_MAX_PROTOCOL_VERSION", "PGCHANNELBINDING",
	"PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGTZ",
	"PGTARGETSESSIONATTRS", "PGLOADBALANCEHOSTS", "PGCONNECT_TIMEOUT", "PGAPPNAME",
	"PGOPTIONS", "PGCLIENTENCODING", "PGGSSENCMODE", "PGKRBSRVNAME", "PGGSSLIB",
	"PGREQUIREPEER", "PGREQUIREAUTH",
}

func (source scopedTelemetryDSN) parse(raw []byte) (*pgx.ConnConfig, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return nil, source.unavailable
	}
	for _, name := range telemetryAmbientVariables {
		if os.Getenv(name) != "" {
			return nil, source.unavailable
		}
	}
	dsn := strings.TrimSpace(string(raw))
	if strings.Contains(dsn, "#") {
		return nil, source.unavailable
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || u.Opaque != "" ||
		u.User == nil || u.User.Username() != source.role || u.Hostname() == "" ||
		u.Port() == "" || u.Path == "" || u.Path == "/" || strings.Contains(u.Path[1:], "/") ||
		u.Fragment != "" || u.RawFragment != "" || u.ForceQuery {
		return nil, source.unavailable
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || len(u.Port()) > 5 || strings.ContainsAny(u.Hostname(), "\x00/\\, \t\r\n") {
		return nil, source.unavailable
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, source.unavailable
	}
	for key, values := range query {
		if key != "sslmode" && key != "sslrootcert" || len(values) != 1 {
			return nil, source.unavailable
		}
	}
	fixture := u.Hostname() == "127.0.0.1" && query.Get("sslmode") == "disable"
	if fixture {
		if _, exists := query["sslrootcert"]; exists {
			return nil, source.unavailable
		}
		query.Set("sslrootcert", "")
	} else if query.Get("sslmode") != "verify-full" || query.Get("sslrootcert") != "system" {
		return nil, source.unavailable
	}
	// Override the driver's default ~/.pgpass and client-certificate paths, not
	// merely the corresponding environment variables. Only system TLS roots are
	// selected above; this runtime has no client-certificate credential source.
	query.Set("passfile", "")
	query.Set("sslcert", "")
	query.Set("sslkey", "")
	query.Set("connect_timeout", "5")
	u.RawQuery = query.Encode()
	parsed, err := pgx.ParseConfigWithOptions(u.String(), pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: []string{
			"host", "port", "user", "password", "database", "sslmode", "sslrootcert", "passfile", "sslcert", "sslkey", "connect_timeout",
		}},
	})
	if err != nil || parsed.User != source.role || parsed.Host != u.Hostname() ||
		parsed.Port != uint16(port) || parsed.Database != u.Path[1:] || len(parsed.Fallbacks) != 0 {
		return nil, source.unavailable
	}
	if fixture {
		if parsed.TLSConfig != nil {
			return nil, source.unavailable
		}
	} else if parsed.TLSConfig == nil || parsed.TLSConfig.InsecureSkipVerify || parsed.TLSConfig.ServerName == "" {
		return nil, source.unavailable
	}
	return parsed, nil
}

func (source scopedTelemetryDSN) read(ctx context.Context, getenv func(string) string) (*pgx.ConnConfig, error) {
	if ctx == nil || ctx.Err() != nil || getenv == nil {
		return nil, source.unavailable
	}
	raw, err := enrollment.PrivateFile(getenv(source.fileVariable), 8192)
	if err != nil {
		return nil, source.unavailable
	}
	defer clear(raw)
	if ctx.Err() != nil {
		return nil, source.unavailable
	}
	return source.parse(raw)
}

type telemetryPruneStep func(context.Context, time.Time) (time.Time, telemetry.Pruned, error)

func waitTelemetryTick(ctx context.Context) bool {
	timer := time.NewTimer(telemetryWorkerInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// The actual call owns the sole slot until it returns, including after its
// context expires. No goroutine, ticker, catch-up queue or replacement worker
// can overlap it. Only a committed, live step advances the authenticated clock.
func runTelemetryPruneLoop(ctx context.Context, step telemetryPruneStep, output io.Writer, wait func(context.Context) bool) error {
	if ctx == nil || step == nil || output == nil || wait == nil {
		return errTelemetryPruneWorker
	}
	var previous time.Time
	for ctx.Err() == nil {
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		now, removed, err := step(bounded, previous)
		if err == nil && (bounded.Err() != nil || now.IsZero() || now.Before(previous) ||
			removed.Events < 0 || removed.Events > 1024 || removed.Windows < 0 || removed.Windows > 1024 ||
			removed.Summaries < 0 || removed.Summaries > 9007199254740991) {
			err = errTelemetryPruneWorker
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if _, writeErr := fmt.Fprintln(output, "telemetry_prune_step_unavailable"); writeErr != nil {
				return errTelemetryPruneWorker
			}
		} else {
			previous = now
			if json.NewEncoder(output).Encode(struct {
				Events    int64 `json:"events"`
				Windows   int64 `json:"windows"`
				Summaries int64 `json:"summaries"`
			}{removed.Events, removed.Windows, removed.Summaries}) != nil {
				return errTelemetryPruneWorker
			}
		}
		if !wait(ctx) {
			return nil
		}
	}
	return nil
}

func runTelemetryPruneWorkerContext(ctx context.Context, getenv func(string) string, output io.Writer) error {
	if ctx == nil || getenv == nil || output == nil {
		return errTelemetryPruneWorker
	}
	if ctx.Err() != nil {
		return nil
	}
	parsed, err := retentionTelemetryDSN.read(ctx, getenv)
	if err != nil {
		return errTelemetryPruneWorker
	}
	if ctx.Err() != nil {
		return nil
	}
	db := stdlib.OpenDB(*parsed)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()
	return runTelemetryPruneLoop(ctx, func(step context.Context, previous time.Time) (time.Time, telemetry.Pruned, error) {
		return telemetry.PruneScheduled(step, db, previous)
	}, output, waitTelemetryTick)
}

func runTelemetryPruneWorker() (err error) {
	defer func() {
		if recover() != nil {
			err = errTelemetryPruneWorker
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runTelemetryPruneWorkerContext(ctx, os.Getenv, os.Stdout)
}

func runTelemetryAggregateSettled() error {
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, 15*time.Second)
	defer cancel()
	parsed, err := analysisTelemetryDSN.read(ctx, os.Getenv)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*parsed)
	db.SetMaxOpenConns(1)
	defer db.Close()
	result, err := telemetry.AggregateSettledHour(ctx, db, time.Now())
	if err != nil {
		return err
	}
	if _, err := fmt.Printf("Telemetry hour summarized: hour=%s groups=%d events=%d\n",
		result.Hour.Format("2006-01-02T15:00Z"), result.Groups, result.Events); err != nil {
		return errTelemetryAggregateSettled
	}
	return nil
}
