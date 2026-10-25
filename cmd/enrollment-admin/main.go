// Owner-only migration/authorization CLI. It is not present in the runtime API role.
package main

import (
	"context"
	"fmt"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"os"
	"time"
)

func run() error {
	c, e := enrollment.ReadConfig(os.Getenv("SYN443_ENROLLMENT_CONFIG"))
	if e != nil {
		return e
	}
	store, e := enrollment.OpenStore(c)
	if e != nil {
		return e
	}
	defer store.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if len(os.Args) != 2 {
		return identity.ErrInvalid
	}
	switch os.Args[1] {
	case "migrate":
		_, e = store.DB.ExecContext(ctx, enrollment.Schema)
		return e
	case "roles":
		_, e = store.DB.ExecContext(ctx, enrollment.Roles)
		return e
	case "authorize":
		raw, e := enrollment.PrivateFile(os.Getenv("SYN443_ENROLLMENT_GRANTS"), 524288)
		if e != nil {
			return e
		}
		var grants []enrollment.Grant
		if identity.DecodeOperatorDocument(raw, &grants) != nil {
			return identity.ErrInvalid
		}
		for _, g := range grants {
			if e = enrollment.Authorize(ctx, store.DB, g, time.Now()); e != nil {
				return e
			}
		}
		return nil
	default:
		return identity.ErrInvalid
	}
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "enrollment_admin_failed")
		os.Exit(1)
	}
}
