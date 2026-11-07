package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var controlSchemaOnce sync.Once
var controlSchema *jsonschema.Schema
var controlSchemaError error

func loadControlSchema() (*jsonschema.Schema, error) {
	controlSchemaOnce.Do(func() {
		raw, e := contracts.Files.ReadFile("v1/control-openapi.json")
		if e != nil {
			controlSchemaError = ErrInvalid
			return
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			controlSchemaError = ErrInvalid
			return
		}
		compiler := jsonschema.NewCompiler()
		const base = "https://contracts.example.invalid/control-openapi.json"
		if compiler.AddResource(base, value) != nil {
			controlSchemaError = ErrInvalid
			return
		}
		controlSchema, controlSchemaError = compiler.Compile(base + "#/components/schemas/Action")
	})
	return controlSchema, controlSchemaError
}

type Verifier interface {
	Verify(context.Context, string, time.Time) (identity.Principal, error)
}
type ExternalAction func(context.Context, string, string, []byte, time.Time) (any, error)

type API struct {
	Invitations          ExternalAction
	Configurations       ExternalAction
	Store                *Store
	Verifier             Verifier
	Origin, AssuranceACR string
	Clock                func() time.Time
	slots                chan struct{}
	mu                   sync.Mutex
	rates                map[string]rate
}
type rate struct {
	Minute int64
	Count  int
}

func NewAPI(store *Store, verifier Verifier, origin, acr string, fixture bool) (*API, error) {
	u, e := url.Parse(origin)
	if store == nil || verifier == nil || e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Scheme != "https" && !(fixture && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "") || len(acr) < 1 || len(acr) > 128 {
		return nil, ErrInvalid
	}
	if _, e := loadControlSchema(); e != nil {
		return nil, ErrUnavailable
	}
	return &API{Store: store, Verifier: verifier, Origin: origin, AssuranceACR: acr, Clock: time.Now, slots: make(chan struct{}, 4), rates: map[string]rate{}}, nil
}
func (a *API) admit(ip string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	minute := now.Unix() / 60
	for key, r := range a.rates {
		if r.Minute < minute-1 {
			delete(a.rates, key)
		}
	}
	r, exists := a.rates[ip]
	if !exists && len(a.rates) >= 512 {
		return false
	}
	if r.Minute != minute {
		r = rate{Minute: minute}
	}
	r.Count++
	a.rates[ip] = r
	return r.Count <= 120
}
func (s *Store) ConsumeAdminProof(ctx context.Context, actor Actor, proof identity.Proof, now time.Time) error {
	if !identifier.MatchString(actor.ID) || len(proof.Thumbprint) != 43 || len(proof.Claims.Jti) < 16 || len(proof.Claims.Jti) > 128 {
		return ErrDenied
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	var allowed bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_acl WHERE actor=$1 AND expires>$2)`, actor.ID, now.Unix()).Scan(&allowed); e != nil {
		return ErrUnavailable
	}
	if !allowed || actor.SessionUntil <= now.Unix() {
		return ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM catalog_proofs WHERE expires<=$1`, now.Unix()); e != nil {
		return ErrUnavailable
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "catalog/proofs/"+actor.ID); e != nil {
		return ErrUnavailable
	}
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM catalog_proofs WHERE actor=$1`, actor.ID).Scan(&count); e != nil {
		return ErrUnavailable
	}
	if count >= 256 {
		return ErrQuota
	}
	result, e := tx.ExecContext(ctx, `INSERT INTO catalog_proofs(actor,jkt,jti,expires) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, actor.ID, proof.Thumbprint, proof.Claims.Jti, min(now.Unix()+120, actor.SessionUntil))
	if e != nil {
		return ErrUnavailable
	}
	n, e := result.RowsAffected()
	if e != nil {
		return ErrUnavailable
	}
	if n != 1 {
		return ErrDenied
	}
	return tx.Commit()
}
func apiFailure(w http.ResponseWriter, e error) {
	status, code := 503, "catalog_unavailable"
	switch {
	case errors.Is(e, ErrDenied), errors.Is(e, identity.ErrInvalid):
		status, code = 403, "catalog_denied"
	case errors.Is(e, ErrInvalid):
		status, code = 400, "catalog_invalid"
	case errors.Is(e, ErrConflict), errors.Is(e, ErrStale):
		status, code = 409, "catalog_revision_conflict"
	case errors.Is(e, ErrQuota):
		status, code = 429, "catalog_quota"
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"code": code})
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" || r.URL.Path != "/v1/control/action" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("DPoP")) != 1 {
		apiFailure(w, ErrDenied)
		return
	}
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || !a.admit(ip, a.Clock()) {
		apiFailure(w, ErrQuota)
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		apiFailure(w, ErrUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	now, e := a.Store.Now(ctx, a.Clock())
	if e != nil {
		apiFailure(w, e)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
	if token == r.Header.Get("Authorization") || len(token) < 24 || len(token) > 16384 {
		apiFailure(w, ErrDenied)
		return
	}
	p, e := a.Verifier.Verify(ctx, token, now)
	if e != nil || !p.HasScope("syn443.control") || p.Expires <= now.Unix() {
		apiFailure(w, ErrDenied)
		return
	}
	const limit = 14*1024*1024 + 65536
	raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || len(raw) > limit {
		apiFailure(w, ErrInvalid)
		return
	}
	proof, e := identity.VerifyProof(r.Header.Get("DPoP"), identity.ProofContext{Method: "POST", URI: a.Origin + r.URL.Path, Token: token, BodyHash: identity.Hash(raw), Now: now})
	if e != nil || proof.Thumbprint != p.Thumbprint {
		apiFailure(w, ErrDenied)
		return
	}
	actor := Actor{ID: identity.Hash([]byte(p.Issuer + "\x00" + p.Subject)), SessionUntil: p.Expires, MFAUntil: p.MFAUntil(a.AssuranceACR, now)}
	if e = a.Store.ConsumeAdminProof(ctx, actor, proof, now); e != nil {
		apiFailure(w, e)
		return
	}
	var action Action
	if identity.DecodeSourceUpload(raw, &action) != nil || action.Version != 1 {
		apiFailure(w, ErrInvalid)
		return
	}
	schema, e := loadControlSchema()
	var wire any
	if e != nil || json.Unmarshal(raw, &wire) != nil || schema.Validate(wire) != nil {
		apiFailure(w, ErrInvalid)
		return
	}
	var value any
	if strings.HasPrefix(action.Action, "invite.") {
		if a.Invitations == nil {
			apiFailure(w, ErrDenied)
			return
		}
		value, e = a.Invitations(ctx, token, r.Header.Get("DPoP"), raw, now)
	} else if action.Action == "configuration.preview.request" || action.Action == "configuration.publish" || action.Action == "configuration.request.get" || action.Action == "configuration.inventory.get" || action.Action == "configuration.layers.draft.get" || action.Action == "configuration.layers.draft.put" || action.Action == "configuration.layers.drafts.list" || action.Action == "configuration.layers.draft.discard" || action.Action == "configuration.history.get" {
		if a.Configurations == nil {
			apiFailure(w, ErrDenied)
			return
		}
		value, e = a.Configurations(ctx, token, r.Header.Get("DPoP"), raw, now)
	} else {
		value, e = a.dispatch(ctx, actor, action, now)
	}
	if e != nil {
		apiFailure(w, e)
		return
	}
	if json.NewEncoder(w).Encode(value) != nil {
		return
	}
}

type Action struct {
	Version   int             `json:"version"`
	Action    string          `json:"action"`
	RequestID string          `json:"requestId"`
	Payload   json.RawMessage `json:"payload"`
}

func (a *API) dispatch(ctx context.Context, actor Actor, action Action, now time.Time) (any, error) {
	decode := func(dst any) error {
		if len(action.Payload) > 65536 || identity.DecodeConfiguration(action.Payload, dst) != nil {
			return ErrInvalid
		}
		return nil
	}
	switch action.Action {
	case "configuration.draft.get":
		var r struct {
			ID string `json:"id"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.GetNetworkDraft(ctx, actor, r.ID, now)
	case "configuration.draft.put":
		var r struct {
			Draft NetworkDraft `json:"draft"`
		}
		if len(action.Payload) > 270336 || identity.DecodeConfiguration(action.Payload, &r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.PutNetworkDraft(ctx, actor, r.Draft, action.RequestID, now)
	case "source.list":
		var r struct {
			Owner string `json:"owner"`
			After string `json:"after"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.ListSources(ctx, actor, r.Owner, r.After, now)
	case "source.snapshot":
		var r struct {
			ID       string `json:"id"`
			Snapshot string `json:"snapshot"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.GetSnapshot(ctx, actor, r.ID, r.Snapshot, now)
	case "job.get":
		var r struct {
			ID string `json:"id"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.GetJob(ctx, actor, r.ID, now)
	case "job.list":
		var r struct {
			SourceID string `json:"sourceId"`
			After    string `json:"after"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.ListJobs(ctx, actor, r.SourceID, r.After, now)
	case "source.get", "source.shares.get":
		var r struct {
			ID string `json:"id"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		if action.Action == "source.get" {
			return a.Store.GetSource(ctx, actor, r.ID, now)
		}
		return a.Store.GetShares(ctx, actor, r.ID, now)
	case "source.put":
		var r struct {
			Source Source      `json:"source"`
			Secret SecretPatch `json:"secret"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.PutSource(ctx, actor, r.Source, r.Secret, action.RequestID, now)
	case "source.sync":
		var r struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.Queue(ctx, actor, r.ID, r.Revision, action.RequestID, nil, now)
	case "source.import":
		var r struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Data     []byte `json:"data"`
		}
		if identity.DecodeSourceUpload(action.Payload, &r) != nil || len(r.Data) > 10*1024*1024 {
			return nil, ErrInvalid
		}
		return a.Store.Queue(ctx, actor, r.ID, r.Revision, action.RequestID, r.Data, now)
	case "source.shares.put":
		var r struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Shares   Shares `json:"shares"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.SetShares(ctx, actor, r.ID, r.Revision, r.Shares, action.RequestID, now)
	case "source.review":
		var r Review
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.ReviewSnapshot(ctx, actor, r, action.RequestID, now)
	case "resource.get":
		var r struct {
			ID string `json:"id"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		resource, impact, e := a.Store.GetResource(ctx, actor, r.ID, now)
		return struct {
			Resource Resource       `json:"resource"`
			Impact   ResourceImpact `json:"impact"`
		}{resource, impact}, e
	case "resource.put":
		var r struct {
			Resource   Resource    `json:"resource"`
			Secret     SecretPatch `json:"secret"`
			ImpactHash string      `json:"impactHash"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return a.Store.PutResource(ctx, actor, r.Resource, r.Secret, r.ImpactHash, action.RequestID, now)
	case "job.cancel":
		var r struct {
			ID string `json:"id"`
		}
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return map[string]bool{"cancelled": true}, a.Store.Cancel(ctx, actor, r.ID, action.RequestID, now)
	default:
		return nil, ErrInvalid
	}
}
