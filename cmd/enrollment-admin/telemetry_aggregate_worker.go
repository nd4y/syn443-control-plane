package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

// The cursor only orders missing hours. The committed summary table is the
// checkpoint across process restarts and competing workers.
func runTelemetryAggregateLoop(ctx context.Context, step func(context.Context, time.Time) (telemetry.SettledAggregate, error),
	output io.Writer, wait func(context.Context) bool) error {
	var after time.Time
	for ctx.Err() == nil {
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		result, err := step(bounded, after)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if !result.Hour.IsZero() {
			after = result.Hour
		}
		var writeErr error
		switch {
		case err != nil:
			_, writeErr = fmt.Fprintln(output, "telemetry_aggregate_step_unavailable")
		case !result.Hour.IsZero():
			_, writeErr = fmt.Fprintf(output, "Telemetry hour summarized: hour=%s groups=%d events=%d\n",
				result.Hour.UTC().Format("2006-01-02T15:00Z"), result.Groups, result.Events)
		}
		if writeErr != nil {
			return errTelemetryAggregateSettled
		}
		if !wait(ctx) {
			return nil
		}
	}
	return nil
}

func runTelemetryAggregateWorker() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := analysisTelemetryDSN.read(ctx, os.Getenv)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()
	return runTelemetryAggregateLoop(ctx, func(step context.Context, after time.Time) (telemetry.SettledAggregate, error) {
		return telemetry.AggregatePendingHour(step, db, time.Now(), after)
	}, os.Stdout, waitTelemetryTick)
}
