package netbirdapi

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const maxAuditBody = 2 * 1024 * 1024

// PeerOwnership is provider evidence, not device/user supplied authorization.
// Its source is the account-bound peer.setupkey.add event: initiator_id is the
// setup-key ID and target_id the peer ID. A friendly hostname/IP is insufficient.
type PeerOwnership struct {
	ResourceID, AccountID                      string
	PeerID, SetupKeyID, OperationName, EventID string
	RegisteredAt, CreatedAt                    time.Time
}

func (PeerOwnership) String() string   { return "NetBirdPeerOwnership([redacted])" }
func (PeerOwnership) GoString() string { return "NetBirdPeerOwnership([redacted])" }

type auditEvent struct {
	ID        remoteID                   `json:"id"`
	At        time.Time                  `json:"timestamp"`
	Code      string                     `json:"activity_code"`
	Initiator string                     `json:"initiator_id"`
	Target    string                     `json:"target_id"`
	Meta      map[string]json.RawMessage `json:"meta"`
}

// Audit has no documented pagination. Stream at most2MiB/10000 bounded events;
// each event still uses the strict duplicate/depth/string-limited decoder.
// Unknown/missing/oversized evidence cannot authorize a peer deletion.
func (c *Client) audit(ctx context.Context, visit func(auditEvent) error) error {
	r, e := http.NewRequestWithContext(ctx, "GET", c.config.APIOrigin+"/api/events/audit", nil)
	if e != nil {
		return failure("invalid_request", false)
	}
	r.Header.Set("Authorization", "Token "+c.config.Token)
	r.Header.Set("Accept", "application/json")
	response, e := c.http.Do(r)
	if e != nil {
		if ctx.Err() != nil || c.closed.Load() {
			return failure("cancelled", false)
		}
		return failure("audit_unavailable", false)
	}
	defer response.Body.Close()
	if ctx.Err() != nil || c.closed.Load() {
		return failure("cancelled", false)
	}
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != 200 || e != nil || media != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return failure("audit_unavailable", false)
	}
	limited := &io.LimitedReader{R: response.Body, N: maxAuditBody + 1}
	d := json.NewDecoder(limited)
	open, e := d.Token()
	if ctx.Err() != nil || c.closed.Load() {
		return failure("cancelled", false)
	}
	if e != nil || open != json.Delim('[') {
		return failure("invalid_audit", false)
	}
	count := 0
	for d.More() {
		if ctx.Err() != nil || c.closed.Load() {
			return failure("cancelled", false)
		}
		count++
		if count > 10000 {
			return failure("audit_limit", false)
		}
		var raw json.RawMessage
		err := d.Decode(&raw)
		if ctx.Err() != nil || c.closed.Load() {
			return failure("cancelled", false)
		}
		if len(raw) > maxBody || limited.N <= 0 {
			return failure("audit_limit", false)
		}
		if err != nil {
			return failure("invalid_audit", false)
		}
		var event auditEvent
		if identity.Decode(raw, &event, false) != nil {
			return failure("invalid_audit", false)
		}
		if e = visit(event); e != nil {
			return e
		}
	}
	if ctx.Err() != nil || c.closed.Load() {
		return failure("cancelled", false)
	}
	if limited.N <= 0 {
		return failure("audit_limit", false)
	}
	close, e := d.Token()
	if e != nil || close != json.Delim(']') {
		return failure("invalid_audit", false)
	}
	if _, e = d.Token(); e != io.EOF || limited.N <= 0 {
		return failure("audit_limit", false)
	}
	if ctx.Err() != nil || c.closed.Load() {
		return failure("cancelled", false)
	}
	return nil
}

func validWindow(start, end time.Time) bool {
	return !start.IsZero() && !end.IsZero() && end.After(start) && end.Sub(start) <= 48*time.Hour
}
func (c *Client) findOwnedPeer(ctx context.Context, name, key string, start, end time.Time) (PeerOwnership, error) {
	var result PeerOwnership
	e := c.audit(ctx, func(event auditEvent) error {
		if event.Code != "peer.setupkey.add" || event.Initiator != key {
			return nil
		}
		var setupName string
		if json.Unmarshal(event.Meta["setup_key_name"], &setupName) != nil || setupName != name {
			return failure("ownership_mismatch", false)
		}
		if !identifier.MatchString(event.Target) || event.At.Before(start.Add(-30*time.Second)) || event.At.After(end.Add(30*time.Second)) || event.ID == "" {
			return failure("ownership_mismatch", false)
		}
		if result.PeerID != "" && result.PeerID != event.Target {
			return failure("ownership_ambiguous", false)
		}
		// Repeated delivery of the same provider event is harmless; a distinct
		// peer under a supposedly one-off key is never silently selected.
		if result.PeerID == "" {
			result = PeerOwnership{ResourceID: c.config.ResourceID, AccountID: c.config.AccountID, PeerID: event.Target, SetupKeyID: key, OperationName: name, EventID: string(event.ID), RegisteredAt: event.At}
		}
		return nil
	})
	if e != nil {
		return PeerOwnership{}, e
	}
	if result.PeerID == "" {
		return PeerOwnership{}, failure("ownership_unavailable", false)
	}
	var peer struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}
	if e = c.request(ctx, "GET", "/api/peers/"+result.PeerID, nil, &peer); e != nil {
		return PeerOwnership{}, e
	}
	if peer.ID != result.PeerID || peer.CreatedAt.IsZero() || peer.CreatedAt.After(result.RegisteredAt.Add(30*time.Second)) || peer.CreatedAt.Before(result.RegisteredAt.Add(-5*time.Minute)) {
		return PeerOwnership{}, failure("peer_identity_mismatch", false)
	}
	result.CreatedAt = peer.CreatedAt
	return result, nil
}

func (c *Client) FindOwnedPeer(ctx context.Context, tag, key string, start, end time.Time) (PeerOwnership, error) {
	name, e := operationName(tag)
	if e != nil || !identifier.MatchString(key) || !validWindow(start, end) {
		return PeerOwnership{}, failure("invalid_operation", false)
	}
	ctx, done, e := c.begin(ctx)
	if e != nil {
		return PeerOwnership{}, e
	}
	defer done()
	if e = c.account(ctx); e != nil {
		return PeerOwnership{}, e
	}
	return c.findOwnedPeer(ctx, name, key, start, end)
}

// RevokeOwnedPeer rediscovers provider ownership and current creation identity;
// it never accepts a request-supplied peer ID as deletion authority. A missing
// peer is idempotently absent; missing/ambiguous audit evidence remains closed.
func (c *Client) RevokeOwnedPeer(ctx context.Context, tag, key string, start, end time.Time) error {
	name, e := operationName(tag)
	if e != nil || !identifier.MatchString(key) || !validWindow(start, end) {
		return failure("invalid_operation", false)
	}
	ctx, done, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	if e = c.account(ctx); e != nil {
		return e
	}
	peer, e := c.findOwnedPeer(ctx, name, key, start, end)
	if e != nil {
		if v, ok := e.(*Error); ok && v.Code == "not_found" {
			return nil
		}
		return e
	}
	var response map[string]any
	return c.request(ctx, "DELETE", "/api/peers/"+peer.PeerID, nil, &response)
}

// RevokeVerifiedPeer accepts only a receipt previously returned by FindOwnedPeer
// and persisted in the broker's immutable, authenticated private journal. It is
// not a device/control API operation. Rechecking account and current creation
// identity permits cleanup after provider audit retention without guessing IDs.
func (c *Client) RevokeVerifiedPeer(ctx context.Context, proof PeerOwnership) error {
	tag := strings.TrimPrefix(proof.OperationName, "syn443-")
	name, e := operationName(tag)
	if e != nil || name != proof.OperationName || proof.ResourceID != c.config.ResourceID || proof.AccountID != c.config.AccountID || !identifier.MatchString(proof.PeerID) || !identifier.MatchString(proof.SetupKeyID) || !identifier.MatchString(proof.EventID) || proof.RegisteredAt.IsZero() || proof.CreatedAt.IsZero() || proof.CreatedAt.After(proof.RegisteredAt.Add(30*time.Second)) || proof.CreatedAt.Before(proof.RegisteredAt.Add(-5*time.Minute)) {
		return failure("invalid_ownership", false)
	}
	ctx, done, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	if e = c.account(ctx); e != nil {
		return e
	}
	var peer struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}
	if e = c.request(ctx, "GET", "/api/peers/"+proof.PeerID, nil, &peer); e != nil {
		if v, ok := e.(*Error); ok && v.Code == "not_found" {
			return nil
		}
		return e
	}
	if peer.ID != proof.PeerID || !peer.CreatedAt.Equal(proof.CreatedAt) {
		return failure("peer_identity_mismatch", false)
	}
	var response map[string]any
	return c.request(ctx, "DELETE", "/api/peers/"+proof.PeerID, nil, &response)
}
