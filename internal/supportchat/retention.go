package supportchat

import (
	"context"
	"database/sql"
	"time"
)

const pruneBatchSize = 128

// PruneExpiredUploads removes one batch. A sender may already hold an upload
// lock while committing the message that links it. Leave such rows to that
// transaction and reconsider them on a later maintenance run.
func PruneExpiredUploads(ctx context.Context, db *sql.DB, now time.Time) (int64, error) {
	result, err := db.ExecContext(ctx, `WITH expired AS (
        SELECT id FROM chat_uploads
        WHERE message_id IS NULL AND expires_at <= $1
        ORDER BY expires_at, id LIMIT $2 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM chat_uploads AS u USING expired
    WHERE u.id = expired.id AND u.message_id IS NULL AND u.expires_at <= $1`, now.Unix(), pruneBatchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DrainExpiredUploads applies a single cutoff to a maintenance invocation.
// Each batch commits separately and a timed-out invocation can be retried.
func DrainExpiredUploads(ctx context.Context, db *sql.DB, cutoff time.Time) (int64, error) {
	var total int64
	for {
		count, err := PruneExpiredUploads(ctx, db, cutoff)
		if err != nil {
			return total, err
		}
		total += count
		if count < pruneBatchSize {
			return total, nil
		}
	}
}
