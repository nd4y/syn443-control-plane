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
