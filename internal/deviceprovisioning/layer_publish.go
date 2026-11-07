package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

type ConfigurationPublishedHead struct {
	Device   string `json:"device"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
}

func (ConfigurationPublishedHead) String() string   { return "ConfigurationPublishedHead([redacted])" }
func (ConfigurationPublishedHead) GoString() string { return "ConfigurationPublishedHead([redacted])" }

// Called only after the independent producer repeats all actual authority and
// source fences in this transaction. No public API accepts a snapshot object.
func (s *configurationLayerSnapshot) publish(ctx context.Context, tx *sql.Tx, w configurationWork, preview, hash string, at time.Time) (json.RawMessage, error) {
	for _, c := range s.Changes {
		if c.OldRevision == c.Revision && c.OldHash == c.Hash {
			continue
		}
		body := s.store.Seal(c.Body, globalLayerAAD(c.Kind, c.ID, c.Revision))
		if _, e := tx.ExecContext(ctx, `INSERT INTO managed_configuration_layer_versions(kind,id,revision,body_hash,body,actor,preview,approved_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.Kind, c.ID, c.Revision, c.Hash, body, w.actor, preview, at.UnixMilli()); e != nil {
			return nil, enrollment.ErrUnavailable
		}
		var result sql.Result
		var e error
		if c.OldRevision == 0 {
			result, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_layer_heads(kind,id,revision,body_hash) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, c.Kind, c.ID, c.Revision, c.Hash)
		} else {
			result, e = tx.ExecContext(ctx, `UPDATE managed_configuration_layer_heads SET revision=$3,body_hash=$4 WHERE kind=$1 AND id=$2 AND revision=$5 AND body_hash=$6`, c.Kind, c.ID, c.Revision, c.Hash, c.OldRevision, c.OldHash)
		}
		if e != nil {
			return nil, enrollment.ErrUnavailable
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return nil, enrollment.ErrConflict
		}
	}
	heads := []ConfigurationPublishedHead{}
	for i, target := range s.Targets {
		b := s.proposal.Bundles[i]
		revision := b.BaseRevision + 1
		if revision > 9007199254740991 {
			return nil, enrollment.ErrDenied
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO managed_configuration_versions(device,revision,owner,jkt,grant_hash,actor,preview,body_hash,approved_at_ms,approval_receipt) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, target.Device, revision, target.Owner, target.Thumbprint, target.GrantHash, w.actor, preview, hash, at.UnixMilli(), w.receipt); e != nil {
			return nil, enrollment.ErrUnavailable
		}
		var result sql.Result
		var e error
		if b.BaseRevision == 0 {
			result, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_heads(device,revision,body_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, target.Device, revision, hash)
		} else {
			result, e = tx.ExecContext(ctx, `UPDATE managed_configuration_heads SET revision=$2,body_hash=$3 WHERE device=$1 AND revision=$4 AND body_hash=$5`, target.Device, revision, hash, b.BaseRevision, b.BaseHash)
		}
		if e != nil {
			return nil, enrollment.ErrUnavailable
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return nil, enrollment.ErrConflict
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM managed_configuration_assignments WHERE device=$1`, target.Device); e != nil {
			return nil, enrollment.ErrUnavailable
		}
		for position, layer := range b.Layers {
			raw, e := json.Marshal(layer)
			if e != nil {
				return nil, enrollment.ErrDenied
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_assignments(device,position,kind,id,revision,body_hash,configuration_revision) VALUES($1,$2,$3,$4,$5,$6,$7)`, target.Device, position, layer.Kind, layer.ID, layer.Revision, configurationHash(raw), revision); e != nil {
				return nil, enrollment.ErrUnavailable
			}
		}
		result, e = tx.ExecContext(ctx, `UPDATE identity_devices SET refresh_after=0,retry_after=0,publication_error='' WHERE id=$1 AND owner=$2 AND jkt=$3 AND active AND approved`, target.Device, target.Owner, target.Thumbprint)
		if e != nil {
			return nil, enrollment.ErrUnavailable
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return nil, enrollment.ErrConflict
		}
		heads = append(heads, ConfigurationPublishedHead{target.Device, revision, hash})
	}
	return json.Marshal(struct {
		Heads []ConfigurationPublishedHead `json:"heads"`
	}{heads})
}
