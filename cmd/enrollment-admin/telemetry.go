package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func runTelemetryPrune() error {
	db, err := openTelemetryDatabase("SYN443_TELEMETRY_RETENTION_DSN_FILE")
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = telemetry.CheckRetentionRole(ctx, db); err != nil {
		return err
	}
	result, err := telemetry.Prune(ctx, db, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("Expired telemetry removed: events=%d windows=%d summaries=%d\n", result.Events, result.Windows, result.Summaries)
	return nil
}

func openTelemetryDatabase(variable string) (*sql.DB, error) {
	raw, err := enrollment.PrivateFile(os.Getenv(variable), 8192)
	if err != nil {
		return nil, identity.ErrInvalid
	}
	defer clear(raw)
	dsn := strings.TrimSpace(string(raw))
	if dsn == "" {
		return nil, identity.ErrInvalid
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, telemetry.ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func parseTelemetryHour(args []string) (time.Time, error) {
	if len(args) != 1 {
		return time.Time{}, identity.ErrInvalid
	}
	hour, err := telemetry.ParseHour(args[0])
	if err != nil {
		return time.Time{}, identity.ErrInvalid
	}
	return hour, nil
}

func runTelemetryAggregate(args []string) error {
	hour, err := parseTelemetryHour(args)
	if err != nil {
		return err
	}
	db, err := openTelemetryDatabase("SYN443_TELEMETRY_ANALYSIS_DSN_FILE")
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = telemetry.CheckAnalysisRole(ctx, db); err != nil {
		return err
	}
	result, err := telemetry.AggregateHour(ctx, db, hour, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("Telemetry hour summarized: groups=%d events=%d\n", result.Groups, result.Events)
	return nil
}

func runTelemetrySummary(args []string) error {
	hour, err := parseTelemetryHour(args)
	if err != nil {
		return err
	}
	db, err := openTelemetryDatabase("SYN443_TELEMETRY_READER_DSN_FILE")
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = telemetry.CheckReportRole(ctx, db); err != nil {
		return err
	}
	report, err := telemetry.ReportHour(ctx, db, hour, time.Now())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}
