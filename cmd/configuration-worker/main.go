// Independent administrative configuration publication. This executable never
// loads enrollment grants/keys or installs NetworkAuthority in device renewal.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/deviceprovisioning"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

var errWorkerFailed = errors.New("configuration_worker_failed")

type configurationWorker interface {
	Now(context.Context, time.Time) (time.Time, error)
	RunOnce(context.Context, time.Time) error
}

func waitTick(ctx context.Context) bool {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// One bounded worker, no overlapping ticks or catch-up queue. Clock failure
// cannot fall back to wall time or execute a publication. Injected wait is an
// internal test seam, never a configuration flag that can remove the budget.
func runLoop(ctx context.Context, worker configurationWorker, output io.Writer, wait func(context.Context) bool) error {
	if ctx == nil || worker == nil || output == nil || wait == nil {
		return errWorkerFailed
	}
	for ctx.Err() == nil {
		step, cancel := context.WithTimeout(ctx, 20*time.Second)
		now, e := worker.Now(step, time.Now())
		if e == nil && (now.IsZero() || step.Err() != nil) {
			e = errWorkerFailed
		}
		if e == nil {
			e = worker.RunOnce(step, now)
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if e != nil {
			_, _ = fmt.Fprintln(output, "configuration_step_unavailable")
		}
		if !wait(ctx) {
			return nil
		}
	}
	return nil
}

func run(ctx context.Context, getenv func(string) string, output io.Writer) error {
	if ctx == nil || ctx.Err() != nil || getenv == nil || output == nil {
		return errWorkerFailed
	}
	c, e := deviceprovisioning.ReadConfigurationWorkerRuntime(getenv("SYN443_CONFIGURATION_WORKER_CONFIG"))
	if e != nil {
		return errWorkerFailed
	}
	key, e := enrollment.PrivateKey(getenv("SYN443_CONFIGURATION_SIGNING_KEY_FILE"))
	if e != nil {
		return errWorkerFailed
	}
	worker, e := deviceprovisioning.OpenConfigurationWorker(ctx, c, getenv("SYN443_CONFIGURATION_KEY_ID"), key, nil)
	if e != nil {
		return errWorkerFailed
	}
	defer worker.Close()
	return runLoop(ctx, worker, output, waitTick)
}

func mainCode() (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "configuration_worker_failed")
			code = 1
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if run(ctx, os.Getenv, os.Stderr) != nil {
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintln(os.Stderr, "configuration_worker_failed")
		return 1
	}
	return 0
}

func main() { os.Exit(mainCode()) }
