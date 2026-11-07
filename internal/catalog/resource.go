package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/remnawave"
	"github.com/nd4y/syn443-control-plane/internal/resources"
)

type Resource struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ProviderType string `json:"providerType"`
	APIVersion   string `json:"apiVersion"`
	Enabled      bool   `json:"enabled"`
	Revision     int64  `json:"revision"`
	State        string `json:"state"`
	LastSync     int64  `json:"lastSync"`
}

func (Resource) String() string   { return "CatalogResource([redacted])" }
func (Resource) GoString() string { return "CatalogResource([redacted])" }
func (r Resource) Validate() error {
	if !sourceIdentifier.MatchString(r.ID) || len(r.Name) < 1 || len(r.Name) > 256 || r.Revision < 0 || r.Revision > 9007199254740991 {
		return ErrInvalid
	}
	switch r.ProviderType {
	case resources.Remnawave:
		if r.APIVersion != "3.4" {
			return ErrInvalid
		}
	case "panel.x-ui", "panel.3x-ui", "overlay.tailscale", "overlay.zerotier":
		if r.Enabled || len(r.APIVersion) > 64 {
			return ErrDenied
		}
	default:
		return ErrInvalid
	}
	return nil
}

type ResourceCredential struct {
	Endpoint        string   `json:"endpoint"`
	Token           string   `json:"token"`
	RootCA          string   `json:"rootCa,omitempty"`
	AllowedNetworks []string `json:"allowedNetworks,omitempty"`
}

func (ResourceCredential) String() string   { return "ResourceCredential([redacted])" }
func (ResourceCredential) GoString() string { return "ResourceCredential([redacted])" }
func readResourceCredential(raw []byte) (ResourceCredential, error) {
	var c ResourceCredential
	if len(raw) == 0 || len(raw) > 65536 || identity.DecodeConfiguration(raw, &c) != nil {
		return c, ErrInvalid
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return c, ErrInvalid
	}
	return c, nil
}
func (c ResourceCredential) Client(r Resource, fixture bool) (*remnawave.Client, error) {
	config, e := (FetchCredential{URL: c.Endpoint, RootCA: c.RootCA, AllowedNetworks: c.AllowedNetworks}).Config(fixture)
	if e != nil {
		return nil, e
	}
	instance := resources.Instance{ResourceID: r.ID, ProviderType: r.ProviderType, APIVersion: r.APIVersion, Endpoint: c.Endpoint, Enabled: true, CredentialRef: r.ID + "/service-token"}
	client, e := remnawave.New(remnawave.Config{Instance: instance, Token: c.Token, Roots: config.Network.Roots, AllowedNetworks: config.Network.Networks, FixtureLoopback: fixture})
	if e != nil {
		return nil, ErrInvalid
	}
	return client, nil
}
func (s *Store) readResource(ctx context.Context, tx *sql.Tx, id string, lock bool) (Resource, []byte, error) {
	var r Resource
	var secret []byte
	query := `SELECT id,name,provider_type,api_version,enabled,revision,state,last_sync,secrets FROM catalog_resources WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	e := tx.QueryRowContext(ctx, query, id).Scan(&r.ID, &r.Name, &r.ProviderType, &r.APIVersion, &r.Enabled, &r.Revision, &r.State, &r.LastSync, &secret)
	if e == sql.ErrNoRows {
		return r, nil, ErrDenied
	}
	if e != nil {
		return r, nil, ErrUnavailable
	}
	raw, e := s.open(secret, aad("resource-secret", id, r.Revision))
	if e != nil {
		return r, nil, e
	}
	return r, raw, nil
}

type ResourceImpact struct {
	Sources int    `json:"sources"`
	Hash    string `json:"hash"`
}

func (s *Store) resourceImpact(ctx context.Context, tx *sql.Tx, id string) (ResourceImpact, error) {
	rows, e := tx.QueryContext(ctx, `SELECT s.id,s.revision,s.enabled,COALESCE(h.revision,0) FROM catalog_sources s LEFT JOIN catalog_share_heads h ON h.source_id=s.id WHERE s.resource_id=$1 ORDER BY s.id`, id)
	if e != nil {
		return ResourceImpact{}, ErrUnavailable
	}
	defer rows.Close()
	var records []struct {
		ID       string
		Revision int64
		Enabled  bool
		Shares   int64
	}
	for rows.Next() {
		var record struct {
			ID       string
			Revision int64
			Enabled  bool
			Shares   int64
		}
		if rows.Scan(&record.ID, &record.Revision, &record.Enabled, &record.Shares) != nil {
			return ResourceImpact{}, ErrUnavailable
		}
		records = append(records, record)
	}
	if rows.Err() != nil {
		return ResourceImpact{}, ErrUnavailable
	}
	raw, _ := json.Marshal(records)
	return ResourceImpact{Sources: len(records), Hash: s.hash(raw)}, nil
}
func (s *Store) GetResource(ctx context.Context, actor Actor, id string, now time.Time) (Resource, ResourceImpact, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Resource{}, ResourceImpact{}, ErrUnavailable
	}
	defer tx.Rollback()
	if e = authorize(ctx, tx, actor, "resources.read", "resource", id, now.Unix(), false); e != nil {
		return Resource{}, ResourceImpact{}, e
	}
	r, _, e := s.readResource(ctx, tx, id, false)
	if e != nil {
		return Resource{}, ResourceImpact{}, e
	}
	impact, e := s.resourceImpact(ctx, tx, id)
	if e != nil {
		return Resource{}, ResourceImpact{}, e
	}
	return r, impact, tx.Commit()
}
func (s *Store) PutResource(ctx context.Context, actor Actor, r Resource, secret SecretPatch, impactHash, request string, now time.Time) (Resource, error) {
	if r.Validate() != nil || r.State != "" || r.LastSync != 0 || !identifier.MatchString(request) {
		return Resource{}, ErrInvalid
	}
	body, _ := json.Marshal(struct {
		Resource Resource
		Secret   SecretPatch
		Impact   string
	}{r, secret, impactHash})
	hash := s.hash(body)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Resource{}, ErrUnavailable
	}
	defer tx.Rollback()
	if e = authorize(ctx, tx, actor, "resources.write", "resource", r.ID, now.Unix(), secret.Operation != "keep"); e != nil {
		return Resource{}, e
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('catalog/resource-writes/v1',0))`); e != nil {
		return Resource{}, ErrUnavailable
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, actor.ID+"/"+request); e != nil {
		return Resource{}, ErrUnavailable
	}
	prior, e := s.priorOperation(ctx, tx, actor.ID, request, "resource.put", r.ID, hash, now.Unix())
	if e != nil {
		return Resource{}, e
	}
	if prior != nil {
		var value Resource
		if json.Unmarshal(prior, &value) != nil {
			return Resource{}, ErrUnavailable
		}
		return value, tx.Commit()
	}
	old, previous, e := s.readResource(ctx, tx, r.ID, true)
	exists := e == nil
	if e != nil && e != ErrDenied {
		return Resource{}, e
	}
	if exists {
		if old.Revision != r.Revision || old.ProviderType != r.ProviderType || old.APIVersion != r.APIVersion {
			return Resource{}, ErrConflict
		}
		if old.Enabled != r.Enabled && actor.MFAUntil <= now.Unix() {
			return Resource{}, ErrDenied
		}
	} else if r.Revision != 0 {
		return Resource{}, ErrConflict
	}
	impact, e := s.resourceImpact(ctx, tx, r.ID)
	if e != nil {
		return Resource{}, e
	}
	if impact.Sources > 0 && (secret.Operation != "keep" || exists && old.Enabled != r.Enabled) && impact.Hash != impactHash {
		return Resource{}, ErrConflict
	}
	raw, e := secret.Apply(previous)
	if e != nil {
		return Resource{}, e
	}
	if r.ProviderType == resources.Remnawave {
		if len(raw) > 0 {
			credential, e := readResourceCredential(raw)
			if e != nil {
				return Resource{}, e
			}
			client, e := credential.Client(r, false)
			if e != nil {
				return Resource{}, e
			}
			client.Close()
			if exists && len(previous) > 0 {
				before, e := readResourceCredential(previous)
				if e != nil {
					return Resource{}, e
				}
				if before.Endpoint != credential.Endpoint && impact.Sources > 0 {
					return Resource{}, ErrConflict
				}
			}
		} else if r.Enabled {
			return Resource{}, ErrInvalid
		}
	} else if len(raw) > 0 {
		return Resource{}, ErrDenied
	}
	if r.Enabled {
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM catalog_resources WHERE enabled AND id<>$1`, r.ID).Scan(&count); e != nil {
			return Resource{}, ErrUnavailable
		}
		if count != 0 {
			return Resource{}, ErrConflict
		}
	}
	r.Revision++
	r.State = "unknown"
	if !r.Enabled {
		r.State = "disabled"
	}
	if r.ProviderType != resources.Remnawave {
		r.State = "not_implemented"
	}
	protected, e := s.seal(raw, aad("resource-secret", r.ID, r.Revision))
	if e != nil {
		return Resource{}, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO catalog_resources(id,revision,provider_type,api_version,name,enabled,secrets,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,name=excluded.name,enabled=excluded.enabled,secrets=excluded.secrets,state=excluded.state`, r.ID, r.Revision, r.ProviderType, r.APIVersion, r.Name, r.Enabled, protected, r.State)
	if e != nil {
		return Resource{}, ErrUnavailable
	}
	if e = s.recordOperation(ctx, tx, actor.ID, request, "resource.put", r.ID, hash, r, now.Unix()); e != nil {
		return Resource{}, ErrUnavailable
	}
	if e = audit(ctx, tx, actor.ID, "resource.put", r.ID, request, "", s.hash(protected), "saved", now.Unix()); e != nil {
		return Resource{}, ErrUnavailable
	}
	return r, tx.Commit()
}

func resourceCurrent(ctx context.Context, tx *sql.Tx, job Job, source Source) error {
	if source.Mode != "resource" {
		if job.ResourceRevision != 0 {
			return ErrStale
		}
		return nil
	}
	var revision int64
	var enabled bool
	e := tx.QueryRowContext(ctx, `SELECT revision,enabled FROM catalog_resources WHERE id=$1 FOR SHARE`, source.ResourceID).Scan(&revision, &enabled)
	if e != nil {
		return ErrUnavailable
	}
	if !enabled || revision != job.ResourceRevision {
		return ErrStale
	}
	return nil
}
func (s *Store) ResourceClient(ctx context.Context, job Job, fixture bool, now time.Time) (*remnawave.Client, string, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, "", ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, job.SourceID, true)
	if e != nil {
		return nil, "", e
	}
	if source.Mode != "resource" || source.Revision != job.SourceRevision {
		return nil, "", ErrStale
	}
	if e = jobCurrent(ctx, tx, job, now.Unix()); e != nil {
		return nil, "", e
	}
	if e = resourceCurrent(ctx, tx, job, source); e != nil {
		return nil, "", e
	}
	r, raw, e := s.readResource(ctx, tx, source.ResourceID, false)
	if e != nil {
		return nil, "", e
	}
	credential, e := readResourceCredential(raw)
	if e != nil {
		return nil, "", e
	}
	client, e := credential.Client(r, fixture)
	if e != nil {
		return nil, "", e
	}
	if e = tx.Commit(); e != nil {
		client.Close()
		return nil, "", ErrUnavailable
	}
	return client, source.ExternalUserID, nil
}
