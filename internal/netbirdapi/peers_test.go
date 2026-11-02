package netbirdapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ownedEvent() auditEvent {
	name, _ := operationName(tag())
	encoded, _ := json.Marshal(name)
	return auditEvent{ID: "event-a", At: now.Add(time.Second), Code: "peer.setupkey.add", Initiator: "key-a", Target: "peer-owned", Meta: map[string]json.RawMessage{"setup_key_name": encoded}}
}
func TestPeerOwnershipUsesSetupKeyEventAndCreationIdentityInsteadOfHostname(t *testing.T) {
	var deletes atomic.Int32
	c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/accounts":
			writeJSON(w, []map[string]string{{"id": "account-a"}})
		case "/api/events/audit":
			writeJSON(w, []auditEvent{{ID: "other", At: now, Code: "peer.rename", Initiator: "issuer|unrelated-user", Target: "other"}, ownedEvent(), ownedEvent()})
		case "/api/peers/peer-owned":
			if r.Method == "DELETE" {
				deletes.Add(1)
				w.WriteHeader(204)
				return
			}
			writeJSON(w, map[string]any{"id": "peer-owned", "name": "renamed-anything", "created_at": now})
		default:
			t.Error("unexpected ownership path")
			w.WriteHeader(404)
		}
	})
	p, e := c.FindOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(24*time.Hour))
	if e != nil || p.PeerID != "peer-owned" || p.SetupKeyID != "key-a" || !p.CreatedAt.Equal(now) {
		t.Fatal("provider ownership unavailable", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", p, p), p.PeerID) {
		t.Fatal("ownership diagnostics leaked identifiers")
	}
	if e = c.RevokeOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(24*time.Hour)); e != nil || deletes.Load() != 1 {
		t.Fatal("owned peer revocation", e)
	}
}
func TestMissingAmbiguousOrForgedPeerEvidenceNeverDeletesAnyPeer(t *testing.T) {
	for _, scenario := range []string{"initiator", "operation-name", "event-type", "missing", "multiple-peers", "event-time", "peer-id", "peer-created", "null-meta", "duplicate-json"} {
		t.Run(scenario, func(t *testing.T) {
			var deletes atomic.Int32
			c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					deletes.Add(1)
					w.WriteHeader(204)
					return
				}
				if r.URL.Path == "/api/accounts" {
					writeJSON(w, []map[string]string{{"id": "account-a"}})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/peers/") {
					id := "peer-owned"
					created := now
					if scenario == "peer-id" {
						id = "foreign"
					}
					if scenario == "peer-created" {
						created = now.Add(time.Hour)
					}
					writeJSON(w, map[string]any{"id": id, "created_at": created})
					return
				}
				event := ownedEvent()
				switch scenario {
				case "initiator":
					event.Initiator = "foreign-key"
				case "operation-name":
					event.Meta["setup_key_name"] = json.RawMessage(`"foreign-operation"`)
				case "event-type":
					event.Code = "peer.sso.add"
				case "missing":
					writeJSON(w, []auditEvent{})
					return
				case "multiple-peers":
					other := ownedEvent()
					other.Target = "another-peer"
					writeJSON(w, []auditEvent{event, other})
					return
				case "event-time":
					event.At = now.Add(48 * time.Hour)
				case "null-meta":
					event.Meta = nil
				case "duplicate-json":
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `[{"id":"a","id":"b"}]`)
					return
				}
				writeJSON(w, []auditEvent{event})
			})
			e := c.RevokeOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(24*time.Hour))
			wantError(t, e, false)
			if deletes.Load() != 0 {
				t.Fatal("unproven peer removed")
			}
		})
	}
}
func TestAuditStreamsBeyondOrdinaryJSONArrayLimitButKeepsByteEntryAndCountBounds(t *testing.T) {
	c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/accounts" {
			writeJSON(w, []map[string]string{{"id": "account-a"}})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/peers/") {
			writeJSON(w, map[string]any{"id": "peer-owned", "created_at": now})
			return
		}
		events := make([]auditEvent, 500)
		for i := range events {
			events[i] = auditEvent{ID: remoteID(fmt.Sprint(i + 1)), At: now, Code: "unrelated", Initiator: "issuer|other"}
		}
		events = append(events, ownedEvent())
		writeJSON(w, events)
	})
	if _, e := c.FindOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(time.Hour)); e != nil {
		t.Fatal("bounded streamed audit", e)
	}
	for _, kind := range []string{"bytes", "entry", "count", "trailing", "root", "status", "compression"} {
		t.Run(kind, func(t *testing.T) {
			bad, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/accounts" {
					writeJSON(w, []map[string]string{{"id": "account-a"}})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "bytes":
					io.WriteString(w, "["+strings.Repeat(" ", maxAuditBody)+"]")
				case "entry":
					io.WriteString(w, `[{"opaque":"`+strings.Repeat("x", maxBody)+`"}]`)
				case "count":
					io.WriteString(w, "["+strings.Repeat(`{"id":"a"},`, 10000)+`{"id":"b"}]`)
				case "trailing":
					io.WriteString(w, "[]{}")
				case "root":
					io.WriteString(w, "null")
				case "status":
					w.WriteHeader(403)
				case "compression":
					w.Header().Set("Content-Encoding", "gzip")
					io.WriteString(w, "[]")
				}
			})
			_, e := bad.FindOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(time.Hour))
			wantError(t, e, false)
		})
	}
}
func TestPeerDeleteLostReplyIsUnknownAndOnlyAnExplicitOwnedRetryCanConfirmAbsence(t *testing.T) {
	var deletes atomic.Int32
	c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/accounts":
			writeJSON(w, []map[string]string{{"id": "account-a"}})
		case "/api/events/audit":
			writeJSON(w, []auditEvent{ownedEvent()})
		case "/api/peers/peer-owned":
			if r.Method == "DELETE" {
				deletes.Add(1)
				conn, _, e := w.(http.Hijacker).Hijack()
				if e != nil {
					t.Error(e)
					return
				}
				conn.Close()
				return
			}
			if deletes.Load() > 0 {
				w.WriteHeader(404)
				return
			}
			writeJSON(w, map[string]any{"id": "peer-owned", "created_at": now})
		}
	})
	wantError(t, c.RevokeOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(time.Hour)), true)
	if deletes.Load() != 1 {
		t.Fatal("peer deletion was silently retried")
	}
	if e := c.RevokeOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(time.Hour)); e != nil || deletes.Load() != 1 {
		t.Fatal("owned absent peer not idempotent", e)
	}
}
func TestPeerLookupInputAndCancellationAreClosedBeforeAnyDelete(t *testing.T) {
	c, _, calls := fixture(t, nil)
	for _, window := range [][2]time.Time{{{}, now}, {now, now}, {now, now.Add(49 * time.Hour)}} {
		_, e := c.FindOwnedPeer(context.Background(), tag(), "key-a", window[0], window[1])
		wantError(t, e, false)
	}
	_, e := c.FindOwnedPeer(context.Background(), "invalid", "key-a", now, now.Add(time.Hour))
	wantError(t, e, false)
	wantError(t, c.RevokeOwnedPeer(context.Background(), tag(), "../peer", now, now.Add(time.Hour)), false)
	if calls.Load() != 0 {
		t.Fatal("invalid ownership search reached provider")
	}
	entered := make(chan struct{})
	blocked, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/accounts" {
			writeJSON(w, []map[string]string{{"id": "account-a"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "[")
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	})
	done := make(chan error, 1)
	go func() {
		_, e := blocked.FindOwnedPeer(context.Background(), tag(), "key-a", now, now.Add(time.Hour))
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("audit did not enter")
	}
	blocked.Close()
	select {
	case e := <-done:
		if wantError(t, e, false).Code != "cancelled" {
			t.Fatal("audit cancellation misclassified")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("audit ignored Close")
	}
}
