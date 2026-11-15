package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Web-only grants are owner input, never accepted by the runtime HTTP API.
// A zero device limit explicitly prevents creating VPN devices or credentials.
type ChatWebAdminGrant struct {
	Issuer            string `json:"issuer"`
	Subject           string `json:"subject"`
	Enabled           *bool  `json:"enabled"`
	Until             int64  `json:"until"`
	ExpectedGrantHash string `json:"expectedGrantHash"`
}

func (g ChatWebAdminGrant) Hash() string {
	if g.Enabled == nil {
		return ""
	}
	raw, _ := json.Marshal(struct {
		Kind, Issuer, Subject string
		Enabled               bool
		Until                 int64
	}{"chat-web-admin.v1", g.Issuer, g.Subject, *g.Enabled, g.Until})
	return identity.Hash(raw)
}

func (g ChatWebAdminGrant) Validate(c Config, now time.Time) error {
	issuer := c.ChatWebIssuer
	if issuer == "" {
		issuer = c.Issuer
	}
	u, e := url.Parse(g.Issuer)
	if c.ChatWebOrigin == "" || c.ValidateChat() != nil || g.Issuer != issuer || e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(g.Issuer, "/") || len(g.Issuer) > 2048 ||
		u.Scheme != "https" && !(c.FixtureHTTP && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "") ||
		g.Subject == "" || len(g.Subject) > 256 || strings.IndexFunc(g.Subject, unicode.IsControl) >= 0 || g.Enabled == nil ||
		now.Unix() < 0 || g.Until <= now.Unix() || g.Until-now.Unix() > 30*86400 ||
		g.ExpectedGrantHash != "" && !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(g.ExpectedGrantHash) {
		return identity.ErrInvalid
	}
	return nil
}

// Account, role and audit commit together. Existing device accounts cannot be
// replaced, and a stale grant cannot restore withdrawn or changed authority.
func AuthorizeChatWebAdmin(ctx context.Context, db *sql.DB, c Config, g ChatWebAdminGrant, now time.Time) (string, error) {
	if e := g.Validate(c, now); e != nil {
		return "", e
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	owner, hash := Owner(g.Issuer, g.Subject), g.Hash()
	r, e := tx.ExecContext(ctx, `INSERT INTO identity_accounts(owner,issuer,subject,enabled,device_limit,valid_until,grant_hash) VALUES($1,$2,$3,$4,0,$5,$6) ON CONFLICT DO NOTHING`, owner, g.Issuer, g.Subject, *g.Enabled, g.Until, hash)
	if e != nil {
		return "", e
	}
	inserted, e := r.RowsAffected()
	if e != nil {
		return "", e
	}
	var issuer, subject, previous string
	var enabled bool
	var limit int
	var until int64
	e = tx.QueryRowContext(ctx, `SELECT issuer,subject,enabled,device_limit,valid_until,grant_hash FROM identity_accounts WHERE owner=$1 FOR UPDATE`, owner).Scan(&issuer, &subject, &enabled, &limit, &until, &previous)
	if e != nil {
		return "", e
	}
	if issuer != g.Issuer || subject != g.Subject || limit != 0 || inserted == 1 && g.ExpectedGrantHash != "" {
		return "", ErrConflict
	}
	if inserted == 0 {
		if previous == hash && enabled == *g.Enabled && until == g.Until {
			var role bool
			if e = tx.QueryRowContext(ctx, `SELECT enabled FROM chat_admins WHERE owner=$1 FOR SHARE`, owner).Scan(&role); e != nil {
				return "", e
			}
			if role != *g.Enabled {
				return "", ErrConflict
			}
			return hash, tx.Commit()
		}
		if previous != g.ExpectedGrantHash {
			return "", ErrConflict
		}
		_, e = tx.ExecContext(ctx, `UPDATE identity_accounts SET enabled=$2,valid_until=$3,grant_hash=$4 WHERE owner=$1`, owner, *g.Enabled, g.Until, hash)
		if e != nil {
			return "", e
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO chat_admins(owner,enabled) VALUES($1,$2) ON CONFLICT(owner) DO UPDATE SET enabled=excluded.enabled`, owner, *g.Enabled)
	if e != nil {
		return "", e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO identity_chat_admin_audit(event_id,owner,actor,issued_at,enabled,valid_until,grant_hash) VALUES($1,$2,current_user,$3,$4,$5,$6)`, random(), owner, now.Unix(), *g.Enabled, g.Until, hash)
	if e != nil {
		return "", e
	}
	return hash, tx.Commit()
}
