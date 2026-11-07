// Isolated provider worker. No HTTP listener, identity sessions or signing key.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

func run() error {
	c, e := enrollment.ReadBrokerRuntimeConfig(os.Getenv("SYN443_OVERLAY_BROKER_CONFIG"))
	if e != nil {
		return e
	}
	store, e := enrollment.OpenStore(enrollment.Config{Database: c.Database, EncryptionKey: c.EncryptionKey})
	if e != nil {
		return e
	}
	defer store.DB.Close()
	resources, e := c.ResourceResolver(store)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	e = store.BrokerRuntimeRole(check)
	if catalog, ok := resources.(*enrollment.BrokerResourceCatalog); e == nil && ok {
		e = catalog.RuntimeRole(check)
	}
	cancel()
	if e != nil {
		return e
	}
	for {
		step, cancel := context.WithTimeout(ctx, 40*time.Second)
		now, err := store.BrokerNow(step, time.Now())
		if err == nil {
			err = store.RunOverlayBrokerOnce(step, resources, now)
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "overlay_step_unavailable")
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
		fmt.Fprintln(os.Stderr, "overlay_worker_failed")
		os.Exit(1)
	}
}
