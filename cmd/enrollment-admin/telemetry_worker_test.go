package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

const telemetryPruneSyntheticDSN = "postgresql://syn443_telemetry_retention@db.example.invalid:5432/syn443?sslmode=verify-full&sslrootcert=system"

func TestTelemetryAggregateWorkerRotatesAfterFailureAndStopsWithoutAnotherStep(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	second := first.Add(time.Hour)
	var output bytes.Buffer
	var steps, waits int
	err := runTelemetryAggregateLoop(ctx, func(step context.Context, after time.Time) (telemetry.SettledAggregate, error) {
		deadline, ok := step.Deadline()
		if !ok || time.Until(deadline) > 15*time.Second || step.Err() != nil {
			t.Fatal("missing database transaction deadline")
		}
		steps++
		switch steps {
		case 1:
			if !after.IsZero() {
				t.Fatal("initial cursor must discover outstanding summaries")
			}
			return telemetry.SettledAggregate{Hour: first}, errors.New("synthetic_private_error")
		case 2:
			if !after.Equal(first) {
				t.Fatal("failed hour starved the following hour")
			}
			return telemetry.SettledAggregate{Hour: second, Hourly: telemetry.Hourly{Groups: 1, Events: 3}}, nil
		case 3:
			if !after.Equal(second) {
				t.Fatal("worker lost successful hour")
			}
			return telemetry.SettledAggregate{}, nil
		default:
			t.Fatal("ran after stop")
			return telemetry.SettledAggregate{}, nil
		}
	}, &output, func(ctx context.Context) bool {
		waits++
		if waits == 3 {
			cancel()
		}
		return ctx.Err() == nil
	})
	want := "telemetry_aggregate_step_unavailable\nTelemetry hour summarized: hour=2026-01-01T02:00Z groups=1 events=3\n"
	if err != nil || steps != 3 || waits != 3 || output.String() != want {
		t.Fatal("wrong result, retry cadence or diagnostic output", err)
	}
}

func TestTelemetryAggregateWorkerRequiresScopedDSNAndExactArguments(t *testing.T) {
	t.Setenv("SYN443_TELEMETRY_ANALYSIS_DSN_FILE", "")
	unused := func(time.Time) error { t.Fatal("manual hour command ran"); return nil }
	if err := runArguments([]string{"telemetry-aggregate-worker"}, unused, unused); err != errTelemetryAggregateSettled {
		t.Fatal("worker did not require its own analysis credential", err)
	}
	if err := runArguments([]string{"telemetry-aggregate-worker", "extra"}, unused, unused); err != identity.ErrInvalid {
		t.Fatal("worker accepted arguments", err)
	}
}

func clearTelemetryPruneEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range telemetryAmbientVariables {
		t.Setenv(name, "")
	}
}

func TestTelemetryPruneWorkerDispatchRequiresExactArgumentsBeforeIO(t *testing.T) {
	called := 0
	witness := errors.New("synthetic_worker_result")
	worker := func() error { called++; return witness }
	blocked := func(time.Time) error { t.Fatal("worker dispatch reached an hour command"); return nil }
	blockedSettled := func() error { t.Fatal("pruning reached scheduled analysis"); return nil }
	if err := runArgumentsWithTelemetryWorkers([]string{"telemetry-prune-worker"}, blocked, blocked, worker, blockedSettled); !errors.Is(err, witness) || called != 1 {
		t.Fatal("worker was not dispatched exactly once before enrollment startup")
	}
	for _, args := range [][]string{
		nil, {"telemetry-prune-worker", "extra"}, {"telemetry-prune-worker", "2024-02-29T16:00Z"},
		{"telemetry-prune-worker", "--config", "synthetic-missing-path"},
	} {
		if err := runArgumentsWithTelemetryWorkers(args, blocked, blocked, worker, blockedSettled); !errors.Is(err, identity.ErrInvalid) {
			t.Fatal("worker accepted extra arguments")
		}
	}
	if called != 1 || runArgumentsWithTelemetryWorkers([]string{"telemetry-prune-worker"}, blocked, blocked, nil, blockedSettled) != identity.ErrInvalid {
		t.Fatal("invalid dispatch invoked a dependency")
	}
}

func TestTelemetrySettledHourDispatchRequiresExactArgumentsBeforeIO(t *testing.T) {
	calls := 0
	witness := errors.New("synthetic_settled_hour_result")
	run := func() error {
		calls++
		return witness
	}
	blocked := func(time.Time) error { t.Fatal("settled command reached a manual hour command"); return nil }
	blockedPrune := func() error { t.Fatal("settled command reached pruning"); return nil }
	if err := runArgumentsWithTelemetryWorkers([]string{"telemetry-aggregate-settled"}, blocked, blocked, blockedPrune, run); err != witness {
		t.Fatal("the command did not reach its handler")
	}
	if err := runArgumentsWithTelemetryWorkers([]string{"telemetry-aggregate-settled", "2026-01-01T00:00Z"}, blocked, blocked, blockedPrune, run); err != identity.ErrInvalid {
		t.Fatal("the scheduled command accepted a caller-supplied hour")
	}
	if err := runArgumentsWithTelemetryWorkers([]string{"telemetry-aggregate-settled"}, blocked, blocked, blockedPrune, nil); err != identity.ErrInvalid {
		t.Fatal("the dispatcher accepted a missing handler")
	}
	if calls != 1 {
		t.Fatal("the dispatcher invoked the scheduled handler outside the valid command")
	}
}

func TestTelemetrySettledHourUsesOnlyScopedAnalysisDSN(t *testing.T) {
	clearTelemetryPruneEnvironment(t)
	input := strings.Replace(telemetryPruneSyntheticDSN, "syn443_telemetry_retention@", "syn443_telemetry_analysis@", 1)
	path := filepath.Join(t.TempDir(), "analysis.dsn")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := analysisTelemetryDSN.read(t.Context(), func(key string) string {
		if key != "SYN443_TELEMETRY_ANALYSIS_DSN_FILE" {
			t.Fatal("the scheduled command attempted a different credential source")
		}
		return path
	})
	if err != nil || parsed == nil || parsed.User != "syn443_telemetry_analysis" ||
		parsed.TLSConfig == nil || parsed.TLSConfig.InsecureSkipVerify || len(parsed.Fallbacks) != 0 {
		t.Fatal("the scheduled command lost the dedicated fully verified connection")
	}
	for _, dsn := range []string{
		telemetryPruneSyntheticDSN,
		strings.Replace(input, "verify-full", "prefer", 1),
	} {
		if parsed, err := analysisTelemetryDSN.parse([]byte(dsn)); parsed != nil || err != errTelemetryAggregateSettled {
			t.Fatal("the scheduled command accepted a widened access path")
		}
	}
}

func TestTelemetryPruneWorkerDSNRequiresExplicitScopedTLSConnection(t *testing.T) {
	clearTelemetryPruneEnvironment(t)
	for _, dsn := range []string{
		telemetryPruneSyntheticDSN,
		strings.Replace(telemetryPruneSyntheticDSN, "postgresql:", "postgres:", 1),
		"postgres://syn443_telemetry_retention@127.0.0.1:17847/postgres?sslmode=disable",
		strings.Replace(telemetryPruneSyntheticDSN, ":5432/", ":1/", 1),
		strings.Replace(telemetryPruneSyntheticDSN, ":5432/", ":65535/", 1),
		telemetryPruneSyntheticDSN + strings.Repeat(" ", 8192-len(telemetryPruneSyntheticDSN)),
	} {
		config, err := retentionTelemetryDSN.parse([]byte(dsn))
		if err != nil || config == nil || config.User != "syn443_telemetry_retention" || config.Database == "" ||
			config.ConnectTimeout != 5*time.Second || len(config.Fallbacks) != 0 {
			t.Fatal("explicit restricted connection was rejected")
		}
		if config.Host != "127.0.0.1" && (config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || config.TLSConfig.ServerName != config.Host) {
			t.Fatal("remote connection lost full TLS verification")
		}
	}
	for _, dsn := range []string{
		"", " ", strings.Repeat("x", 8193), "host=db.example.invalid user=syn443_telemetry_retention dbname=syn443 sslmode=verify-full",
		strings.Replace(telemetryPruneSyntheticDSN, "postgresql:", "https:", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "syn443_telemetry_retention@", "syn443_identity_owner@", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "syn443_telemetry_retention@", "", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "db.example.invalid", "", 1),
		strings.Replace(telemetryPruneSyntheticDSN, ":5432", "", 1),
		strings.Replace(telemetryPruneSyntheticDSN, ":5432", ":0", 1),
		strings.Replace(telemetryPruneSyntheticDSN, ":5432", ":65536", 1),
		strings.Replace(telemetryPruneSyntheticDSN, ":5432", ":005432", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "/syn443?", "/?", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "/syn443?", "/syn443/other?", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "verify-full", "verify-ca", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "verify-full", "require", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "verify-full", "prefer", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "verify-full", "disable", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "&sslrootcert=system", "", 1),
		strings.Replace(telemetryPruneSyntheticDSN, "sslrootcert=system", "sslrootcert=synthetic-path", 1),
		telemetryPruneSyntheticDSN + "&sslmode=verify-full", telemetryPruneSyntheticDSN + "#fragment", telemetryPruneSyntheticDSN + "#",
		telemetryPruneSyntheticDSN + "&service=synthetic", telemetryPruneSyntheticDSN + "&passfile=synthetic-path",
		telemetryPruneSyntheticDSN + "&sslcert=synthetic-path", telemetryPruneSyntheticDSN + "&sslkey=synthetic-path",
		strings.Replace(telemetryPruneSyntheticDSN, "db.example.invalid", "db.example.invalid,other.example.invalid", 1),
		"postgres://syn443_telemetry_retention@localhost:5432/postgres?sslmode=disable",
		"postgres://syn443_telemetry_retention@[::1]:5432/postgres?sslmode=disable",
		"postgres://syn443_telemetry_retention@127.0.0.1:5432/postgres?sslmode=prefer",
		"postgres://syn443_telemetry_retention@127.0.0.1:5432/postgres?sslmode=disable&sslrootcert=system",
	} {
		if config, err := retentionTelemetryDSN.parse([]byte(dsn)); err != errTelemetryPruneWorker || config != nil {
			t.Fatal("unsafe or incomplete connection obtained a runtime")
		}
	}
}

func TestTelemetryPruneWorkerRejectsAmbientCredentialAndServiceSources(t *testing.T) {
	clearTelemetryPruneEnvironment(t)
	for _, name := range telemetryAmbientVariables {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "synthetic-untrusted-ambient-input")
			if config, err := retentionTelemetryDSN.parse([]byte(telemetryPruneSyntheticDSN)); err != errTelemetryPruneWorker || config != nil {
				t.Fatal("ambient connection input was accepted")
			}
		})
	}
	// Explicit URLs still override default credential-file paths in the actual
	// parsed connection string, even when there is no ambient libpq setting.
	config, err := retentionTelemetryDSN.parse([]byte(telemetryPruneSyntheticDSN))
	if err != nil || !strings.Contains(config.ConnString(), "passfile=") || !strings.Contains(config.ConnString(), "sslcert=") || !strings.Contains(config.ConnString(), "sslkey=") {
		t.Fatal("driver defaults retained an implicit credential file")
	}
}

func TestTelemetryPruneWorkerReadsOnlyOwnerProtectedDedicatedDSN(t *testing.T) {
	clearTelemetryPruneEnvironment(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "retention-dsn")
	if err := os.WriteFile(path, []byte(telemetryPruneSyntheticDSN), 0600); err != nil {
		t.Fatal("could not write synthetic owner file")
	}
	var names []string
	getenv := func(name string) string { names = append(names, name); return path }
	if config, err := retentionTelemetryDSN.read(t.Context(), getenv); err != nil || config == nil ||
		len(names) != 1 || names[0] != "SYN443_TELEMETRY_RETENTION_DSN_FILE" {
		t.Fatal("worker read enrollment inputs or rejected its dedicated owner file")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal("could not change synthetic permissions")
	}
	if _, err := retentionTelemetryDSN.read(t.Context(), getenv); err != errTelemetryPruneWorker {
		t.Fatal("nonprivate DSN file was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal("could not restore synthetic permissions")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, 8193), 0600); err != nil {
		t.Fatal("could not write synthetic oversized input")
	}
	if _, err := retentionTelemetryDSN.read(t.Context(), getenv); err != errTelemetryPruneWorker {
		t.Fatal("oversized DSN file was accepted")
	}
	if err := os.WriteFile(path, []byte(telemetryPruneSyntheticDSN), 0600); err != nil {
		t.Fatal("could not restore valid synthetic symlink target")
	}
	link := filepath.Join(directory, "retention-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal("could not create synthetic symlink")
	}
	if _, err := retentionTelemetryDSN.read(t.Context(), func(string) string { return link }); err != errTelemetryPruneWorker {
		t.Fatal("symlink DSN was accepted")
	}
	var output bytes.Buffer
	names = nil
	if err := runTelemetryPruneWorkerContext(t.Context(), func(name string) string {
		names = append(names, name)
		return filepath.Join(directory, "missing")
	}, &output); err != errTelemetryPruneWorker || len(names) != 1 || names[0] != "SYN443_TELEMETRY_RETENTION_DSN_FILE" || output.Len() != 0 {
		t.Fatal("failed startup read unrelated authority or leaked private failure")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runTelemetryPruneWorkerContext(ctx, func(string) string {
		t.Fatal("cancelled startup read a private file")
		return ""
	}, &output); err != nil {
		t.Fatal("ordinary cancelled startup became a process failure")
	}
}

func TestTelemetryPruneWorkerSerialStepsUseOneDeadlineAndPostExitWait(t *testing.T) {
	var output bytes.Buffer
	var order []string
	var contexts []context.Context
	base := time.Unix(1_800_000_000, 0).UTC()
	calls := 0
	step := func(ctx context.Context, previous time.Time) (time.Time, telemetry.Pruned, error) {
		calls++
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= 14*time.Second || remaining > 15*time.Second || ctx.Err() != nil {
			t.Fatal("pruning did not receive the fixed live step deadline")
		}
		if calls == 1 && !previous.IsZero() || calls == 2 && previous != base {
			t.Fatal("authenticated clock did not carry across steps")
		}
		contexts = append(contexts, ctx)
		order = append(order, "step")
		return base.Add(time.Duration(calls-1) * time.Minute), telemetry.Pruned{Events: 1024, Windows: 1024, Summaries: 7}, nil
	}
	waits := 0
	err := runTelemetryPruneLoop(t.Context(), step, &output, func(context.Context) bool {
		if contexts[len(contexts)-1].Err() == nil {
			t.Fatal("post-completion wait began with a live step")
		}
		order = append(order, "wait")
		waits++
		return waits < 2
	})
	if err != nil || strings.Join(order, ",") != "step,wait,step,wait" || telemetryWorkerInterval != time.Minute ||
		output.String() != strings.Repeat("{\"events\":1024,\"windows\":1024,\"summaries\":7}\n", 2) {
		t.Fatal("worker overlapped, changed cadence or rendered nonnumeric data")
	}
}

func TestTelemetryPruneWorkerFailuresKeepAuthenticatedClockAndFiniteOutput(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	for _, failure := range []string{"sql", "zero", "rewind", "negative", "unsafe-count", "expired-context"} {
		t.Run(failure, func(t *testing.T) {
			var output bytes.Buffer
			calls := 0
			ctx := t.Context()
			var cancel context.CancelFunc
			if failure == "expired-context" {
				// Parent deadline expires while the synchronous step owns the slot;
				// cancellation must not report its returned value as a success.
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			}
			step := func(step context.Context, previous time.Time) (time.Time, telemetry.Pruned, error) {
				calls++
				if calls == 1 {
					return base, telemetry.Pruned{}, nil
				}
				if previous != base {
					t.Fatal("failed result replaced the last authenticated clock")
				}
				if calls > 2 {
					return base.Add(time.Minute), telemetry.Pruned{}, nil
				}
				switch failure {
				case "sql":
					return base.Add(time.Hour), telemetry.Pruned{Events: 1}, errors.New("synthetic-private-dsn-and-sql-detail")
				case "zero":
					return time.Time{}, telemetry.Pruned{}, nil
				case "rewind":
					return base.Add(-time.Second), telemetry.Pruned{}, nil
				case "negative":
					return base, telemetry.Pruned{Events: -1}, nil
				case "unsafe-count":
					return base, telemetry.Pruned{Summaries: 9007199254740992}, nil
				default:
					cancel()
					return base.Add(time.Hour), telemetry.Pruned{Events: 1}, nil
				}
			}
			waits := 0
			if err := runTelemetryPruneLoop(ctx, step, &output, func(context.Context) bool { waits++; return waits < 3 }); err != nil {
				t.Fatal("a bounded failed step terminated the worker")
			}
			zero := "{\"events\":0,\"windows\":0,\"summaries\":0}\n"
			want := zero + "telemetry_prune_step_unavailable\n" + zero
			if failure == "expired-context" {
				want = zero
			}
			if output.String() != want {
				t.Fatal("failed step leaked a source or reported uncommitted counters")
			}
		})
	}
}

func TestTelemetryPruneWorkerCancellationRetainsActualStepOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started, observedCancellation, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseStep := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseStep()
	actualExit, done := make(chan struct{}), make(chan error, 1)
	var output bytes.Buffer
	calls, waits := 0, 0
	go func() {
		done <- runTelemetryPruneLoop(ctx, func(step context.Context, _ time.Time) (time.Time, telemetry.Pruned, error) {
			calls++
			close(started)
			<-step.Done()
			close(observedCancellation)
			<-release
			close(actualExit)
			return time.Unix(1_800_000_000, 0), telemetry.Pruned{Events: 1}, nil
		}, &output, func(context.Context) bool { waits++; return true })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("immediate step did not start")
	}
	cancel()
	select {
	case <-observedCancellation:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not reach the actual operation")
	}
	select {
	case <-done:
		t.Fatal("worker released ownership before actual step exit")
	default:
	}
	releaseStep()
	select {
	case err := <-done:
		if err != nil || calls != 1 || waits != 0 || output.Len() != 0 {
			t.Fatal("cancelled operation spawned a replacement or emitted committed counts")
		}
		select {
		case <-actualExit:
		default:
			t.Fatal("process returned before its operation")
		}
	case <-time.After(time.Second):
		t.Fatal("actual exit did not finish cancellation")
	}
	if waitTelemetryTick(ctx) {
		t.Fatal("cancelled idle wait retained work")
	}
}

type telemetryPruneFailingWriter struct{}

func (telemetryPruneFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-private-output-detail")
}

func TestTelemetryPruneWorkerRejectsInvalidLoopDependenciesAndOutputFailure(t *testing.T) {
	step := func(context.Context, time.Time) (time.Time, telemetry.Pruned, error) {
		return time.Unix(1_800_000_000, 0), telemetry.Pruned{}, nil
	}
	wait := func(context.Context) bool { t.Fatal("failed output started another tick"); return false }
	var output bytes.Buffer
	if runTelemetryPruneLoop(nil, step, &output, wait) != errTelemetryPruneWorker ||
		runTelemetryPruneLoop(t.Context(), nil, &output, wait) != errTelemetryPruneWorker ||
		runTelemetryPruneLoop(t.Context(), step, nil, wait) != errTelemetryPruneWorker ||
		runTelemetryPruneLoop(t.Context(), step, &output, nil) != errTelemetryPruneWorker ||
		runTelemetryPruneLoop(t.Context(), step, telemetryPruneFailingWriter{}, wait) != errTelemetryPruneWorker {
		t.Fatal("invalid dependency or private output failure was accepted")
	}
	failingStep := func(context.Context, time.Time) (time.Time, telemetry.Pruned, error) {
		return time.Time{}, telemetry.Pruned{}, errors.New("synthetic-private-sql-detail")
	}
	if runTelemetryPruneLoop(t.Context(), failingStep, telemetryPruneFailingWriter{}, wait) != errTelemetryPruneWorker ||
		runTelemetryPruneWorkerContext(nil, os.Getenv, &output) != errTelemetryPruneWorker ||
		runTelemetryPruneWorkerContext(t.Context(), nil, &output) != errTelemetryPruneWorker ||
		runTelemetryPruneWorkerContext(t.Context(), os.Getenv, nil) != errTelemetryPruneWorker ||
		readTelemetryPruneWorkerInvalidDependencies(t) == false {
		t.Fatal("invalid startup or failure-output dependency was accepted")
	}
}

func readTelemetryPruneWorkerInvalidDependencies(t *testing.T) bool {
	t.Helper()
	_, nilContext := retentionTelemetryDSN.read(nil, os.Getenv)
	_, nilLookup := retentionTelemetryDSN.read(t.Context(), nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, cancelled := retentionTelemetryDSN.read(ctx, func(string) string {
		t.Fatal("cancelled private reader consulted an input")
		return ""
	})
	return nilContext == errTelemetryPruneWorker && nilLookup == errTelemetryPruneWorker && cancelled == errTelemetryPruneWorker
}
