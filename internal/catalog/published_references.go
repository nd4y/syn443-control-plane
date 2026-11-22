package catalog

import (
	"context"
	"database/sql"
)

// A NULL profile means an earlier configuration has not yet been indexed.
// Until the publisher reads that committed plan, preserve the current source's
// existing profiles when assessing a removal.
func publishedReferences(ctx context.Context, tx *sql.Tx, source string) (map[string]bool, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT profile_id FROM catalog_dependencies WHERE source_id=$1
		UNION SELECT profile_id FROM catalog_published_references WHERE source_id=$1 OR source_id IS NULL`, source)
	if err != nil {
		return nil, false, ErrUnavailable
	}
	defer rows.Close()
	refs := map[string]bool{}
	var pending bool
	for rows.Next() {
		var id sql.NullString
		if err = rows.Scan(&id); err != nil {
			return nil, false, ErrUnavailable
		}
		if id.Valid {
			refs[id.String] = true
		} else {
			pending = true
		}
	}
	if rows.Err() != nil {
		return nil, false, ErrUnavailable
	}
	return refs, pending, nil
}

// A source administrator may see its profile identifiers but no recipient
// names, unrelated sources, or mutable configuration bodies.
type SourceReferencePreview struct {
	ProfileIDs []string `json:"profileIds"`
	More       bool     `json:"more"`
	Incomplete bool     `json:"incomplete"`
}

func sourceReferencePreview(ctx context.Context, tx *sql.Tx, source string) (SourceReferencePreview, error) {
	result := SourceReferencePreview{ProfileIDs: []string{}}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM catalog_published_references WHERE source_id IS NULL)`).Scan(&result.Incomplete); err != nil {
		return result, ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, `SELECT profile_id FROM catalog_dependencies WHERE source_id=$1
		UNION SELECT profile_id FROM catalog_published_references WHERE source_id=$1 ORDER BY profile_id LIMIT 33`, source)
	if err != nil {
		return result, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !identifier.MatchString(id) {
			return SourceReferencePreview{}, ErrUnavailable
		}
		if len(result.ProfileIDs) == 32 {
			result.More = true
			break
		}
		result.ProfileIDs = append(result.ProfileIDs, id)
	}
	if rows.Err() != nil {
		return SourceReferencePreview{}, ErrUnavailable
	}
	return result, nil
}
