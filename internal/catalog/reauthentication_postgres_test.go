//go:build postgres

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestCatalogAssuranceChallengeRequiresTheLiveObjectGrantAndCannotMutate(t *testing.T) {
	store, _, actor, now := databaseFixture(t)
	actor.MFAUntil = now.Unix()
	tx, e := store.DB.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = authorize(context.Background(), tx, actor, "sources.write", "user", "synthetic-user", now.Unix(), true); !errors.Is(e, ErrReauthentication) || !errors.Is(e, ErrDenied) {
		t.Fatal("missing MFA became authority", e)
	}
	if e = authorize(context.Background(), tx, actor, "sources.write", "user", "synthetic-user", now.Unix(), false); e != nil {
		t.Fatal("ordinary scoped read was unnecessarily challenged", e)
	}
	actor.ID = "ungranted-actor"
	if e = authorize(context.Background(), tx, actor, "sources.write", "user", "synthetic-user", now.Unix(), true); !errors.Is(e, ErrDenied) || errors.Is(e, ErrReauthentication) {
		t.Fatal("unknown actor received a scope hint", e)
	}
}

func TestCatalogHTTPAssuranceDenialIsTypedWhileRevocationRemainsAPlainDenial(t *testing.T) {
	f := adminHTTPFixture(t)
	source := sourceExample(f.Now)
	f.Verifier.Principal.ACR = "0"
	f.Verifier.Principal.Methods = nil
	payload := map[string]any{"source": source, "secret": SecretPatch{Operation: "keep"}}
	var reply map[string]string
	if e := json.Unmarshal(f.call(t, "source.put", payload, 403), &reply); e != nil || reply["code"] != "catalog_reauthentication_required" {
		t.Fatal("missing scoped assurance challenge", e)
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_sources`).Scan(&count); e != nil || count != 0 {
		t.Fatal("assurance denial mutated a source", e)
	}
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, f.Actor.ID); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(f.call(t, "source.put", payload, 403), &reply); e != nil || reply["code"] != "catalog_denied" {
		t.Fatal("revoked authority was mistaken for fresh-login recovery", e)
	}
}
