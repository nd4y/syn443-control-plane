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
	case "chat-admin":
		raw, e := enrollment.PrivateFile(os.Getenv("SYN443_CHAT_ADMIN_GRANT"), 8192)
		if e != nil {
			return e
		}
		var g struct {
			Issuer  string `json:"issuer"`
			Subject string `json:"subject"`
			Enabled bool   `json:"enabled"`
		}
		if identity.Decode(raw, &g, true) != nil || g.Issuer != c.Issuer || len(g.Subject) < 1 || len(g.Subject) > 256 {
			return identity.ErrInvalid
		}
		_, e = store.DB.ExecContext(ctx, `INSERT INTO chat_admins(owner,enabled) VALUES($1,$2) ON CONFLICT(owner) DO UPDATE SET enabled=excluded.enabled`, enrollment.Owner(g.Issuer, g.Subject), g.Enabled)
		return e
	case "chat-cleanup":
		_, e = store.DB.ExecContext(ctx, `DELETE FROM chat_uploads WHERE id IN (SELECT id FROM chat_uploads WHERE message_id IS NULL AND expires_at<=$1 ORDER BY expires_at LIMIT 128)`, time.Now().Unix())
		return e
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
