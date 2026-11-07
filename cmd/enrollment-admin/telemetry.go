package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func runTelemetryPrune() error {
	raw, err := enrollment.PrivateFile(os.Getenv("SYN443_TELEMETRY_RETENTION_DSN_FILE"), 8192)
	if err != nil {
		return identity.ErrInvalid
	}
	defer clear(raw)
	dsn := strings.TrimSpace(string(raw))
	if dsn == "" {
		return identity.ErrInvalid
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return telemetry.ErrUnavailable
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
	fmt.Printf("Expired telemetry removed: events=%d windows=%d\n", result.Events, result.Windows)
	return nil
}
