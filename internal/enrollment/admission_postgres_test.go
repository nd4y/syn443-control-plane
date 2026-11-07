//go:build postgres

package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func admissionFixture(t *testing.T) (*fixture, *Publisher, Session, snapshot) {
	t.Helper()
	f := newFixture(t, 2)
	session, _, token := f.register(t, key(t))
	f.v.mu.Lock()
	principal := f.v.principals[token]
	principal.Expires = f.now.Unix() + 3600
	f.v.principals[token] = principal
	f.v.mu.Unlock()
	p := f.publisher()
	p.Configurations = fixtureConfigurationAuthority(func(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error) {
		return nil, ErrConfigurationUnassigned
	})
	var s snapshot
	s.Device = session.DeviceID
	if e := fixtureOwner.QueryRow(`SELECT owner,jkt,request_body,receipt,approved,revision FROM identity_devices WHERE id=$1`, s.Device).Scan(&s.Owner, &s.Jkt, &s.Raw, &s.Receipt, &s.Approved, &s.Revision); e != nil {
		t.Fatal(e)
	}
	s.Grant = f.grant.Hash()
	return f, p, session, s
}

func TestIndependentIdentityAdmissionFreezesRequestWithoutMintingPolicy(t *testing.T) {
	f, p, session, s := admissionFixture(t)
	if e := p.publish(context.Background(), session.DeviceID, f.now); e != nil {
		t.Fatal(e)
	}
	var approved bool
	var publication, body, receipt []byte
	var revision int64
	var code string
	if e := fixtureOwner.QueryRow(`SELECT approved,publication,revision,request_body,receipt,publication_error FROM identity_devices WHERE id=$1`, s.Device).Scan(&approved, &publication, &revision, &body, &receipt, &code); e != nil || !approved || publication != nil || revision != 0 || string(body) != string(s.Raw) || string(receipt) != string(s.Receipt) || code != "configuration_pending" {
		t.Fatal("admission minted authority or rewrote identity", e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET request_body='{}' WHERE id=$1`, s.Device); e == nil {
		t.Fatal("admitted original request mutable")
	}
	if e := p.admitIdentity(context.Background(), s, f.grant, nil, f.now.Unix()+60, f.now); e != nil {
		t.Fatal("lost admission reply not idempotent", e)
	}
	if e := p.publish(context.Background(), session.DeviceID, f.now); !errors.Is(e, ErrConfigurationUnassigned) {
		t.Fatal("unassigned authority fell back to raw grant", e)
	}
	if e := p.RunOnce(context.Background(), f.now.Add(31*time.Second)); e != nil {
		t.Fatal(e)
	}
	if e := fixtureOwner.QueryRow(`SELECT publication FROM identity_devices WHERE id=$1`, s.Device).Scan(&publication); e != nil || publication != nil {
		t.Fatal("retry minted unsigned/default policy", e)
	}
}

func TestIdentityAdmissionRechecksReceiptOwnerGrantRevocationAndDeadline(t *testing.T) {
	for _, kind := range []string{"receipt", "body", "device", "account", "grant", "expired", "cancelled", "wrong-role", "fence", "late-expiry", "quota"} {
		t.Run(kind, func(t *testing.T) {
			f, p, _, s := admissionFixture(t)
			ctx := context.Background()
			until := f.now.Unix() + 60
			var fence ApprovalFence
			exec := func(query string, args ...any) {
				t.Helper()
				if _, e := fixtureOwner.Exec(query, args...); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "receipt":
				exec(`UPDATE identity_devices SET receipt=receipt||decode('00','hex') WHERE id=$1`, s.Device)
			case "body":
				exec(`UPDATE identity_devices SET request_body=request_body||decode('20','hex') WHERE id=$1`, s.Device)
			case "device":
				exec(`UPDATE identity_devices SET active=false WHERE id=$1`, s.Device)
			case "account":
				exec(`UPDATE identity_accounts SET enabled=false WHERE owner=$1`, s.Owner)
			case "grant":
				exec(`UPDATE identity_accounts SET grant_hash='changed' WHERE owner=$1`, s.Owner)
			case "expired":
				until = f.now.Unix()
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "wrong-role":
				p.Store = f.store
			case "fence":
				fence = &fixtureConfigurationFence{lock: func(context.Context, *sql.Tx, time.Time) error { return ErrDenied }}
			case "late-expiry":
				until = f.now.Unix() + 1
				fence = &fixtureConfigurationFence{lock: func(context.Context, *sql.Tx, time.Time) error { time.Sleep(1100 * time.Millisecond); return nil }}
			case "quota":
				f.register(t, key(t))
				f.grant.DeviceLimit = 1
				if e := Authorize(ctx, fixtureOwner, f.grant, f.now); e != nil {
					t.Fatal(e)
				}
				s.Grant = f.grant.Hash()
			}
			if e := p.admitIdentity(ctx, s, f.grant, fence, until, f.now); e == nil {
				t.Fatal("stale admission accepted", kind)
			}
			var approved bool
			var publication []byte
			if e := fixtureOwner.QueryRow(`SELECT approved,publication FROM identity_devices WHERE id=$1`, s.Device).Scan(&approved, &publication); e != nil || approved || publication != nil {
				t.Fatal("rejected admission leaked authority", e)
			}
		})
	}
}
