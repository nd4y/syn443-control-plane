// The source worker has no enrollment, user-grant or signing authority.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

func run() error {
	raw, e := enrollment.PrivateFile(os.Getenv("SYN443_SOURCE_CONFIG"), 65536)
	if e != nil {
		return e
	}
	c, e := catalog.ParseRuntimeConfig(raw)
	if e != nil {
		return e
	}
	store, e := catalog.OpenStore(c)
	if e != nil {
		return e
	}
	defer store.DB.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	e = store.RuntimeRole(check, true)
	cancel()
	if e != nil {
		return e
	}
	worker := catalog.Worker{Store: store, FixtureLoopback: c.FixtureLoopback}
	nextSchedule := time.Time{}
	for {
		step, cancel := context.WithTimeout(ctx, 50*time.Second)
		now, err := store.Now(step, time.Now())
		if err == nil && !now.Before(nextSchedule) {
			_, err = store.Schedule(step, now)
			if err == nil {
				nextSchedule = now.Add(time.Minute)
			}
		}
		var job catalog.Job
		if err == nil {
			job, err = worker.ProcessOne(step)
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "source_step_unavailable")
		}
		if err == nil && job.ID != "" {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "source_worker_failed")
		os.Exit(1)
	}
}
