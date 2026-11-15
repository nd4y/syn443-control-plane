package catalog

import (
	"fmt"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
	"testing"
	"time"
)

func TestSourceSelectionValidityAndInputBounds(t *testing.T) {
	now := time.Unix(1800000000, 0)
	target := SelectionTarget{"user-a", "device-a"}
	refs := []ProfileReference{{"source-a", "profile-a"}}
	if validSelection(target, refs, "wifi", now.Unix()+1, now) != nil {
		t.Fatal("valid selection rejected")
	}
	for _, bad := range []struct {
		target SelectionTarget
		refs   []ProfileReference
		mode   string
		until  int64
	}{
		{SelectionTarget{}, refs, "wifi", now.Unix() + 1}, {target, nil, "wifi", now.Unix() + 1}, {target, append(refs, refs...), "wifi", now.Unix() + 1}, {target, []ProfileReference{{"bad/source", "a"}}, "wifi", now.Unix() + 1}, {target, []ProfileReference{{"source-a", "bad/profile"}}, "wifi", now.Unix() + 1}, {target, refs, "unknown", now.Unix() + 1}, {target, refs, "wifi", now.Unix()}, {target, refs, "wifi", now.Unix() + 604801}, {target, make([]ProfileReference, 65), "wifi", now.Unix() + 1},
	} {
		if validSelection(bad.target, bad.refs, bad.mode, bad.until, now) == nil {
			t.Fatal("invalid selection input admitted")
		}
	}
	many := []ProfileReference{}
	for i := 0; i < 33; i++ {
		many = append(many, ProfileReference{fmt.Sprintf("source-%d", i), "profile-a"})
	}
	if validSelection(target, many, "wifi", now.Unix()+1, now) == nil {
		t.Fatal("source count budget bypassed")
	}
	s := sourceExample(now)
	s.Revision = 1
	s.ActiveSnapshot = "snapshot-a"
	s.AccessState = "allowed"
	snapshot := Snapshot{ID: s.ActiveSnapshot, SourceID: s.ID, SourceRevision: 1, State: "active", ObservedAt: now.Unix(), ValidUntil: now.Unix() + 600}
	if until, e := sourceSelectionValid(s, snapshot, "wifi", now); e != nil || until != snapshot.ValidUntil {
		t.Fatal("valid permitted snapshot rejected", e)
	}
	for _, change := range []func(*Source, *Snapshot){func(s *Source, _ *Snapshot) { s.Enabled = false }, func(s *Source, _ *Snapshot) { s.ActiveSnapshot = "" }, func(s *Source, _ *Snapshot) { s.AccessState = "revoked" }, func(_ *Source, p *Snapshot) { p.ID = "other" }, func(_ *Source, p *Snapshot) { p.SourceID = "other" }, func(_ *Source, p *Snapshot) { p.State = "quarantined" }, func(_ *Source, p *Snapshot) { p.SourceRevision = 2 }, func(_ *Source, p *Snapshot) { p.ObservedAt = now.Unix() + 31 }, func(_ *Source, p *Snapshot) { p.Quota = subscriptions.Quota{Known: true, Used: 10, Limit: 10} }, func(_ *Source, p *Snapshot) { p.ValidUntil = now.Unix() }, func(_ *Source, p *Snapshot) { p.Quota.ExpiresAt = now.Unix() }} {
		a, b := s, snapshot
		if a.Revision == 0 {
			a.Revision = 1
		}
		change(&a, &b)
		if _, e := sourceSelectionValid(a, b, "wifi", now); e == nil {
			t.Fatal("unusable snapshot admitted")
		}
	}
	s.Revision = 1
	snapshot.Quota.ExpiresAt = now.Unix() + 10
	if until, e := sourceSelectionValid(s, snapshot, "wifi", now); e != nil || until != now.Unix()+10 {
		t.Fatal("upstream expiry not clamped")
	}
	if _, e := sourceSelectionValid(s, snapshot, "cellular", now); e == nil {
		t.Fatal("network mode grant bypassed")
	}
}
