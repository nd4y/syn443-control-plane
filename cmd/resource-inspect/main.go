// resource-inspect is an owner CLI, never a device-facing credential endpoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/nd4y/syn443-control-plane/internal/remnawave"
	"github.com/nd4y/syn443-control-plane/internal/resources"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("resource-inspect", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "owner-only resource configuration")
	user := f.String("user-id", "", "owner-authorized external user ID")
	export := f.String("private-output", "", "explicit NEW private snapshot file; includes subscription credentials")
	fail := func(err error) int {
		var e *resources.Error
		if !errors.As(err, &e) {
			e = &resources.Error{Code: "invalid_owner_request"}
		}
		json.NewEncoder(out).Encode(map[string]any{"ok": false, "code": e.Code, "retryable": e.Retryable})
		return 1
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 || *config == "" || *user == "" {
		return fail(resources.Failure("invalid_owner_request", false))
	}
	c, e := remnawave.NewFromOwnerFile(*config)
	if e != nil {
		return fail(e)
	}
	defer c.Close()
	// Resource ID comes exclusively from the verified owner configuration, not CLI/device input.
	b := c.Binding(*user)
	s, e := c.ReadAssignment(ctx, b)
	if e != nil {
		return fail(e)
	}
	if *export != "" {
		if !filepath.IsAbs(*export) {
			return fail(resources.Failure("invalid_private_output", false))
		}
		// Never replace a prior authorized snapshot on success or provider failure.
		file, e := os.OpenFile(*export, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return fail(resources.Failure("private_output_exists_or_unavailable", false))
		}
		payload, e := json.Marshal(s)
		if e == nil {
			_, e = file.Write(append(payload, '\n'))
		}
		if e == nil {
			e = file.Sync()
		}
		closed := file.Close()
		if e != nil || closed != nil {
			os.Remove(*export)
			return fail(resources.Failure("private_output_failed", false))
		}
	}
	json.NewEncoder(out).Encode(map[string]any{"ok": true, "profileCount": len(s.Links), "expiresAt": s.ExpiresAt, "observedAt": s.ObservedAt, "privateExport": *export != ""})
	return 0
}
func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout)) }
